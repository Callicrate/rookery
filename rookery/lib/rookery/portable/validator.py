from __future__ import annotations

import ast
import datetime as dt
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Iterator

import tomllib

from .environment import EnvironmentPolicyError, _read_dotenv_compat, minimal_child_environment
from .event_env import (
    CORE_EVENT_ENVIRONMENT_SCHEMA,
    RELEASE_ADAPTER_CATALOG_ENV_KEYS,
    RELEASE_EXTENSION_CATALOG_ENV_KEYS,
    event_environment_names,
    extension_environment_catalog_names,
    resolve_event_environment,
)
from .manifest import profile_has_platform_assumption, resolve_manifest
from .preparation import APPROVED_MANAGED_SEARXNG_IMAGE
from .registry import load_registry, validate_admission
from .util import load_json, tree_hash

RUNTIME_NAME_FRAGMENTS = (
    ".tmp.",
    ".lock",
    ".pid",
    ".sqlite3-wal",
    ".sqlite3-shm",
    ".stdout",
    ".stderr",
)
ENV_ASSIGNMENT = re.compile(r"(?m)^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(.*?)\s*$")
CREDENTIAL_VALUE = re.compile(
    r"(?:"
    r"(?:^|\s)(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"
    r"|(?:^|[^A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9_]{8,}|AIza[A-Za-z0-9_-]{20,}|"
    r"sk_(?:live|test)_[A-Za-z0-9_-]{8,}|(?:AKIA|ASIA)[A-Z0-9]{12,})(?:$|[^A-Za-z0-9_])"
    r"|(?:^|[^A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    r"|authorization\s*[:=]\s*(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"
    r")",
    re.IGNORECASE,
)
CREDENTIALED_URL = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@")
PRIVATE_KEY_BLOCK = re.compile(r"(?im)^-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY(?: BLOCK)?-----")
ABSOLUTE_LOCAL = re.compile(r"(?<![A-Za-z0-9_])/(?:home|Users|mnt|private/tmp|var/folders)/[^\s`'\"]+")
DEPRECATED_BRANDING = (
    "ctf " + "soul " + "swarm",
    "ctf " + "swarm",
    "swarm " + "pack",
    "portable " + "pack",
    "this " + "pack",
    "the " + "pack",
)
OLD_PROJECT_NAMES = tuple(re.compile(rf"\b{re.escape(value)}\b", re.I) for value in DEPRECATED_BRANDING)
ALLOWED_SECRET_EXAMPLES = {
    "unknown",
    "replace-me",
    "example-token",
    "fixture-token",
    "your-token",
    "changeme",
}
SENSITIVE_CREDENTIAL_SEGMENTS = {
    "AUTH",
    "AUTHENTICATION",
    "AUTHN",
    "AUTHORIZATION",
    "AUTHZ",
    "BEARER",
    "CLEARANCE",
    "COOKIE",
    "CREDENTIAL",
    "CREDENTIALS",
    "PASS",
    "PASSCODE",
    "PASSWORD",
    "PASSPHRASE",
    "PASSWD",
    "SECRET",
    "SESSION",
    "SESSIONID",
    "TICKET",
    "TOKEN",
}
RELEASE_CORE_ENV_KEYS = frozenset(
    {
        "PLATFORM_ADAPTER",
        "EVENT_EXTENSIONS",
        "AUTOMATION_PERMITTED_ACTION_KINDS",
        "QUEUE_AUTOMATION",
        "QUEUE_CADENCE_SECONDS",
        "QUEUE_JITTER_SECONDS",
        "QUEUE_LATENCY_SECONDS",
        "QUEUE_WATCH_INTERVAL_SECONDS",
        "CONCURRENCY_MAX_WORKERS",
        "CONCURRENCY_MAX_JOBS",
        "CODEX_SUBAGENT_THREADS",
        "COMPUTE_TOTAL_UNITS",
        "COMPUTE_INTERACTIVE_RESERVE",
        "WRITEUP_MODE",
        "ROOKERY_PREPARE_MODE",
        "ROOKERY_PREPARE_INSTALL",
        "ROOKERY_INSTALL_RECOMMENDED",
        "ROOKERY_INSTALL_HEAVY",
        "ROOKERY_ALLOW_INSTALL_NETWORK",
        "ROOKERY_PREPARE_NETWORK_ENV_KEYS",
        "ROOKERY_PREPARE_TIMEOUT",
        "ROOKERY_SUDO",
        "SEARXNG_MODE",
        "SEARXNG_URL",
        "SEARXNG_LOCAL_PORT",
        "SEARXNG_IMAGE",
        "SEARXNG_CONTAINER_ENGINE",
        "SEARXNG_START_TIMEOUT",
        "SEARXNG_NETWORK_ENV_KEYS",
        "BROWSER_MODE",
        "BROWSER_CDP_URL",
        "BROWSER_BIDI_URL",
        "BROWSER_GATEWAY_URL",
        "BROWSER_EXECUTABLE",
        "CHROME_BIN",
        "BROWSER_ENV_KEYS",
        "ROCKYOU_PATH",
        "SECLISTS_PATH",
        "CREDENTIAL_HEALTH_ARGV",
        "NEAR_MISS_PROBE_ARGV",
        "CODEX_AUTH_MODE",
        "CODEX_PROVIDER_ENV_KEYS",
        "CODEX_NETWORK_ENV_KEYS",
        "TRANSIT_SOURCE_NETWORK_ENV_KEYS",
        "NCQ_NETWORK_ENV_KEYS",
        "ROOKERY_MEASUREMENT_BASELINE_PATH",
    }
)
RELEASE_NAMES_ONLY_ENV_CONTROLS = frozenset(
    {
        "CODEX_PROVIDER_ENV_KEYS",
        "CODEX_NETWORK_ENV_KEYS",
        "TRANSIT_SOURCE_NETWORK_ENV_KEYS",
        "NCQ_NETWORK_ENV_KEYS",
        "ROOKERY_PREPARE_NETWORK_ENV_KEYS",
        "SEARXNG_NETWORK_ENV_KEYS",
        "BROWSER_ENV_KEYS",
    }
)
# The root template is a public, blank-only catalogue. Keep this fixed set so
# an extracted release containing one selected optional adapter can still
# validate its inert documentation for the other adapters it did not package.
# Full-source validation below checks this list against every reviewed adapter
# descriptor, so a new schema field cannot silently become accepted.
RELEASE_ADAPTER_CATALOG_IDS = frozenset(
    {"ctfd", "ctfd_browser", "ctfd_browser_gateway", "htb", "immersive", "skillbit"}
)
RELEASE_EXTENSION_CATALOG_IDS = frozenset({"guacamole", "koth"})
OPERATIONAL_CONFIGURATION_SEGMENTS = {
    "ACK",
    "ACKNOWLEDGED",
    "ARGV",
    "CONFIG",
    "CONFIGURATION",
    "ENABLED",
    "FORMAT",
    "HEALTH",
    "INTERVAL",
    "MODE",
    "PATH",
    "POLICY",
    "PROVIDER",
    "REQUIRED",
    "SCHEME",
    "SECONDS",
    "SOURCE",
    "STATUS",
    "TIMEOUT",
    "TTL",
    "TYPE",
}
CHILD_ENVIRONMENT_LAUNCH_METHODS = frozenset({"Popen", "run", "call", "check_call", "check_output"})
ASYNC_CHILD_ENVIRONMENT_LAUNCH_METHODS = frozenset({"create_subprocess_exec", "create_subprocess_shell"})
AMBIENT_ENVIRONMENT_APIS = frozenset({"os.getenv", "os.putenv", "os.unsetenv"})
DYNAMIC_IMPORT_CALLS = frozenset({"__import__", "builtins.__import__", "importlib.import_module"})
# A dynamically loaded module can expose a second process-launch surface that
# the ordinary import-alias analysis cannot inspect.  A statically known,
# non-launch module remains data-only; unknown values fail closed instead.
DANGEROUS_DYNAMIC_IMPORT_ROOTS = frozenset(
    {"asyncio", "builtins", "concurrent", "multiprocessing", "os", "pty", "subprocess"}
)
DYNAMIC_LAUNCH_LOOKUP_MODULES = frozenset(
    {
        "asyncio",
        "builtins",
        "concurrent.futures",
        "importlib",
        "multiprocessing",
        "multiprocessing.pool",
        "os",
        "pty",
        "subprocess",
    }
)
# These module namespaces expose either process launch or raw network effects.
# A literal member read from their module dictionary is equivalent to an
# attribute read for this bounded AST lint.  Ordinary dictionaries are not in
# this set and remain data-only.  Computed members on these modules fail closed
# because they could select an unreviewed launch or network callable.
REFLECTIVE_CAPABILITY_MODULES = frozenset(
    {
        *DYNAMIC_LAUNCH_LOOKUP_MODULES,
        "http.client",
        "socket",
        "urllib",
        "urllib.request",
        "websocket",
    }
)
MODULE_DICTIONARY_GETTER_PREFIX = "rookery.module-dictionary-getter."
CAPABILITY_MODULE_DICTIONARY_PREFIX = "rookery.capability-module-dictionary."
PROCESS_CONCURRENCY_CALLS = frozenset(
    {
        "concurrent.futures.ProcessPoolExecutor",
        "multiprocessing.Pool",
        "multiprocessing.Process",
        "multiprocessing.pool.Pool",
    }
)
UNSAFE_BUILTIN_CODE_CALLS = frozenset({"eval", "exec", "builtins.eval", "builtins.exec"})

# The static gate is intentionally broad: ``bin`` entries are routinely
# extensionless Python programs, while optional adapter and extension bundles
# carry both modules and executable helpers.  Do not reduce this to a hand
# maintained file list: a newly shipped helper is exactly the surface this gate
# must make visible before release.
SHIPPED_PYTHON_SOURCE_ROOTS = (
    "lib/rookery/portable",
    "bin",
    "adapters",
    "extensions",
    "services",
)
# ``bin`` helpers need structural discovery rather than a suffix allowlist.
# PyPy is deliberately a *candidate*, not an approved Rookery interpreter:
# accepting it here lets the isolated-CPython gates emit a deterministic
# finding instead of silently omitting the helper from static review.
PYTHON_FAMILY_SHEBANG = re.compile(rb"\A#![^\r\n]*\b(?:python|pypy)(?:[0-9.]+)?(?:\s|$)", re.I)
PYTHON_SHEBANG = PYTHON_FAMILY_SHEBANG
ISOLATED_PYTHON_SHEBANG = re.compile(rb"\A#![^\r\n]*\bpython(?:[0-9.]+)?\s+-I\s+-S(?:\s|$)", re.I)
ISOLATED_CORE_PYTHON_SHEBANG = re.compile(rb"\A#![^\r\n]*\bpython(?:[0-9.]+)?(?:\s+[^\r\n]*)?$", re.I)
# Optional adapter/extension helpers load Rookery after a local library-path
# bootstrap. ``env -S`` belongs to the shebang grammar; Python itself receives
# exactly ``-I -B``. Do not add Python's ``-S`` here: system site packages are
# intentionally available for optional integrations, while ``-I`` rejects
# ambient Python paths and customisations.
ISOLATED_ADAPTER_EXTENSION_PYTHON_SHEBANG = b"#!/usr/bin/env -S python3 -I -B"
SCRIPT_DERIVED_SOURCE_ROOT = re.compile(rb"(?m)^SOURCE_ROOT\s*=\s*Path\(__file__\)\.resolve\(\)\.parents\[3\]\s*$")
RUNTIME_WORKSPACE_ROOT = re.compile(rb"(?m)^ROOT\s*=\s*Path\.cwd\(\)\s*$")
SCRIPT_DERIVED_LIBRARY_BOOTSTRAP = re.compile(
    rb"(?m)^sys\.path\.insert\(0,\s*str\(SOURCE_ROOT\s*/\s*[\"']lib[\"']\)\)\s*$"
)
CWD_LIBRARY_BOOTSTRAP = re.compile(rb"(?:(?<![A-Za-z0-9_])ROOT|Path\.cwd\(\))\s*/\s*[\"']lib[\"']")
BOUND_RUNTIME_WORKSPACE_CALL = re.compile(rb"(?m)^\s*require_bound_runtime_workspace\(ROOT\)\s*$")
RUNTIME_ROOT_BIN_REFERENCE = re.compile(rb"(?:(?<![A-Za-z0-9_])ROOT)\s*/\s*[\"']bin(?:[\"']|/)")
ISOLATED_SHELL_PYTHON_BOOTSTRAP = re.compile(
    rb"(?:^|[;\n])\s*(?:exec\s+)?python(?:[0-9.]+)?\s+-I\s+-S(?:\s|$)",
    re.I,
)
SHELL_PYTHON_INVOCATION = re.compile(
    rb"(?:^|[;\n])\s*(?:(?:exec|command)\s+)?"
    rb"(?:(?:/usr/bin/env)\s+(?:-S\s+)?)?(?:/usr/bin/)?python(?:[0-9.]+)?(?:\s|$)",
    re.I,
)
STATIC_SOURCE_MAX_BYTES = 8 * 1024 * 1024

# These commands are public controls or directly cross a trust boundary.  A
# Python interpreter reached through any of them must be isolated *before*
# Python evaluates PYTHONPATH, PYTHONHOME, or site customisations.  Other
# shipped helpers retain their established shebangs until individually moved;
# this narrow list prevents a broad, compatibility-breaking rewrite.
TRUSTED_STARTUP_ENTRYPOINTS = (
    "go",
    "run-codex",
    "bin/rookery",
    "bin/build-release",
    "bin/rookery-codex-launch",
)

# The extracted release has one private, operator-edited launch input. A clean
# source checkout deliberately contains only its reviewed template.
RELEASE_CONFIGURATION_TEMPLATES = MappingProxyType(
    {
        ".env": ".env.example",
    }
)
LEGACY_EVENT_FILE = "event.json"


def _core_bin_python_shebang_errors(relative: str, raw: bytes) -> list[str]:
    """Require every shipped core Python helper to isolate startup and bytecode.

    Core helpers are extensionless often enough that a curated list would miss
    exactly the next executable added to ``bin``. This deliberately covers
    only Python-shebang files in that one directory; adapter and extension
    entrypoints retain their separately owned compatibility contracts.
    """

    if not relative.startswith("bin/") or not PYTHON_SHEBANG.match(raw):
        return []
    first_line = raw.splitlines()[0] if raw else b""
    if not ISOLATED_CORE_PYTHON_SHEBANG.match(first_line) or not all(
        re.search(rb"(?:^|\s)" + option + rb"(?:\s|$)", first_line) for option in (rb"-I", rb"-B")
    ):
        return ["core Python entrypoint must use an isolated -I and -B shebang: " + relative]
    return []


def _is_adapter_extension_bin_entrypoint(relative: str) -> bool:
    """Return whether a path is an optional-bundle executable helper."""

    parts = relative.split("/")
    return len(parts) >= 4 and parts[0] in {"adapters", "extensions"} and parts[2] == "bin"


def _imports_rookery(raw: bytes) -> bool:
    """Recognise direct Rookery imports without matching comments or strings."""

    try:
        tree = ast.parse(raw.decode("utf-8"))
    except (SyntaxError, UnicodeDecodeError):
        # The primary source scan reports deterministic decode/syntax errors.
        # This narrower policy cannot safely classify invalid source.
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module == "rookery" or bool(node.module and node.module.startswith("rookery.")):
                return True
        elif isinstance(node, ast.Import):
            if any(alias.name == "rookery" or alias.name.startswith("rookery.") for alias in node.names):
                return True
    return False


def _adapter_extension_python_shebang_errors(relative: str, raw: bytes) -> list[str]:
    """Require isolated startup for optional Python helpers importing Rookery.

    Standalone helpers such as Guacamole's console lease are intentionally
    excluded because they do not import the Rookery package. Discovery is
    structural rather than list-based so a new optional entrypoint cannot
    silently bypass the startup boundary.
    """

    if not _is_adapter_extension_bin_entrypoint(relative) or not PYTHON_SHEBANG.match(raw):
        return []
    first_line = raw.splitlines()[0] if raw else b""
    if first_line != ISOLATED_ADAPTER_EXTENSION_PYTHON_SHEBANG:
        return ["adapter/extension Rookery Python entrypoint must use exact env -S python3 -I -B shebang: " + relative]
    return []


def _adapter_extension_script_root_errors(relative: str, raw: bytes) -> list[str]:
    """Require a script-derived library root before helper workspace access.

    Adapter and extension helpers retain ``ROOT = Path.cwd()`` for runtime
    state/output semantics, but their import authority must come only from the
    immutable script path.  This narrowly prevents a caller-owned ``cwd/lib``
    package from executing before binding/configuration checks without making a
    claim about replacement of the released script itself.
    """

    if not _is_adapter_extension_bin_entrypoint(relative) or not PYTHON_SHEBANG.match(raw):
        return []
    errors: list[str] = []
    if len(SCRIPT_DERIVED_SOURCE_ROOT.findall(raw)) != 1:
        errors.append(
            "adapter/extension Rookery helper must derive one SOURCE_ROOT from "
            f"Path(__file__).resolve().parents[3]: {relative}"
        )
    if len(RUNTIME_WORKSPACE_ROOT.findall(raw)) != 1:
        errors.append("adapter/extension Rookery helper must retain runtime ROOT = Path.cwd(): " + relative)
    if len(SCRIPT_DERIVED_LIBRARY_BOOTSTRAP.findall(raw)) != 1:
        errors.append("adapter/extension Rookery helper must import only SOURCE_ROOT/lib: " + relative)
    if CWD_LIBRARY_BOOTSTRAP.search(raw):
        errors.append("adapter/extension Rookery helper must not select cwd/lib for imports: " + relative)
    if len(BOUND_RUNTIME_WORKSPACE_CALL.findall(raw)) != 1:
        errors.append(
            "adapter/extension Rookery helper must verify runtime launch binding before operations: " + relative
        )
    if RUNTIME_ROOT_BIN_REFERENCE.search(raw):
        errors.append("adapter/extension Rookery helper must not execute cwd/bin helpers: " + relative)
    return errors


# DNS lookup and TCP connection are one authority boundary.  Only the pinned
# transport may own raw socket/urllib primitives; all callers receive its
# scope-checked plans or transport object.  This is an implementation boundary
# rather than a filename waiver for adapters, helpers, or generic utilities.
SCOPED_TRANSPORT_MODULE = "lib/rookery/portable/scoped_transport.py"
RAW_URLOPEN_ALLOWLIST = {SCOPED_TRANSPORT_MODULE: "DNS-pinned transport"}
GENERIC_URLOPEN_TARGETS = frozenset(
    {
        "urllib.request.FancyURLopener",
        "urllib.request.OpenerDirector",
        "urllib.request.URLopener",
        "urllib.request.build_opener",
        "urllib.request.install_opener",
    }
)
RAW_URLLIB_TRANSFER_TARGETS = frozenset({"urllib.request.urlopen", "urllib.request.urlretrieve", "urllib.urlretrieve"})
RAW_HTTP_CLIENT_TARGETS = frozenset({"http.client.HTTPConnection", "http.client.HTTPSConnection"})
RAW_SOCKET_DNS_TARGETS = frozenset(
    {
        "socket.getaddrinfo",
        "socket.gethostbyaddr",
        "socket.gethostbyname",
        "socket.gethostbyname_ex",
    }
)
NETCAT_EXECUTABLES = frozenset({"nc", "ncat", "netcat"})
CANONICAL_SCOPE_READ_ALLOWLIST = frozenset(
    {
        "lib/rookery/portable/cli.py",
        "lib/rookery/portable/scope.py",
    }
)

# A launched process needs a stable way to locate its workspace before the
# environment resolver exists.  This is the sole compatibility bootstrap read;
# it is deliberately exact so a second ambient read cannot hide behind it.
ROOKERY_ROOT_BOOTSTRAP = ("lib/rookery/portable/cli.py", "workspace_root")

# ``_bounded_codex_probe`` is the one central exception to the public
# ``ChildEnvironment.values`` launch shape.  It receives the already-built,
# bounded mapping from the Codex admission gate, captures bounded output, and
# never exposes a general-purpose caller interface.  No adapter, extension, or
# executable entrypoint is included here.
INTERNAL_BOUNDED_SPAWN = (
    "lib/rookery/portable/environment.py",
    "_bounded_codex_probe",
)


def _dotted_name(node: ast.AST, aliases: dict[str, str]) -> str:
    """Return a canonical dotted name for direct imports and common aliases."""

    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value, aliases)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    """Resolve imports needed by the structural launch/environment checks."""

    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                local = item.asname or item.name.split(".", 1)[0]
                canonical = item.name if item.asname else item.name.split(".", 1)[0]
                aliases[local] = canonical
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                if item.name == "*":
                    continue
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"
    for node in ast.walk(tree):
        if not isinstance(node, (ast.With, ast.AsyncWith)):
            continue
        for item in node.items:
            if item.optional_vars is None:
                continue
            canonical = _network_client_constructor_target(item.context_expr, aliases)
            if not canonical:
                continue
            for name in _assignment_names(item.optional_vars):
                aliases[name] = canonical
    # A local name can retain a dangerous imported callable without using an
    # import alias.  Resolve only direct module/member and literal-getattr
    # assignments; wider dataflow would create false assurances instead of a
    # deterministic release gate.
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        canonical = _dotted_name(value, aliases) or _getattr_dotted_name(value, aliases)
        concurrency_target = _process_concurrency_target(value, aliases)
        if concurrency_target:
            canonical = concurrency_target
        network_constructor = _network_client_constructor_target(value, aliases)
        if network_constructor:
            canonical = network_constructor
        socket_member = _socket_instance_getattr_target(value, aliases)
        if socket_member:
            canonical = socket_member
        capability_module_dictionary = _capability_module_dictionary(value, aliases)
        if capability_module_dictionary:
            canonical = f"{CAPABILITY_MODULE_DICTIONARY_PREFIX}{capability_module_dictionary}"
        module_dictionary_getter = _module_dictionary_getter_target(value, aliases)
        if module_dictionary_getter:
            canonical = module_dictionary_getter
        module_dictionary_member = _module_dictionary_target(value, aliases)
        if module_dictionary_member:
            canonical = module_dictionary_member
        if not canonical and isinstance(value, ast.Call):
            function = value.func
            if (
                _dotted_name(function, aliases) in {"getattr", "builtins.getattr"}
                and value.args
                and _dotted_name(value.args[0], aliases) in DYNAMIC_LAUNCH_LOOKUP_MODULES
            ):
                canonical = "rookery.dynamic-launch-api"
        if not canonical:
            continue
        if isinstance(node, ast.Assign):
            targets = node.targets
        else:
            targets = [node.target]
        for target in targets:
            for name in _assignment_names(target):
                aliases[name] = canonical
    return aliases


def _annotation_is_child_environment(annotation: ast.AST | None) -> bool:
    return bool(annotation) and _dotted_name(annotation, {}).endswith("ChildEnvironment")


def _assignment_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        return {name for item in node.elts for name in _assignment_names(item)}
    return set()


def _child_environment_factory_names(tree: ast.AST, aliases: dict[str, str]) -> set[str]:
    """Return central factories and local functions typed to return the object."""

    factories = {
        "build_child_environment",
        "minimal_child_environment",
        "codex_launcher_environment",
        "vpn_watch_environment",
    }
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _annotation_is_child_environment(node.returns):
            factories.add(node.name)
    return factories


def _call_is_child_environment_factory(node: ast.AST, aliases: dict[str, str], factories: set[str]) -> bool:
    if not isinstance(node, ast.Call):
        return False
    return _dotted_name(node.func, aliases).rsplit(".", 1)[-1] in factories


def _child_environment_names(tree: ast.AST, aliases: dict[str, str]) -> set[str]:
    """Collect names whose construction is statically attributable to the type."""

    names: set[str] = set()
    factories = _child_environment_factory_names(tree, aliases)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            arguments = node.args
            for argument in (
                *arguments.posonlyargs,
                *arguments.args,
                *arguments.kwonlyargs,
            ):
                if _annotation_is_child_environment(argument.annotation):
                    names.add(argument.arg)
            if arguments.vararg and _annotation_is_child_environment(arguments.vararg.annotation):
                names.add(arguments.vararg.arg)
            if arguments.kwarg and _annotation_is_child_environment(arguments.kwarg.annotation):
                names.add(arguments.kwarg.arg)
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            value = node.value
            if _call_is_child_environment_factory(value, aliases, factories):
                targets: tuple[ast.AST, ...]
                if isinstance(node, ast.Assign):
                    targets = tuple(node.targets)
                else:
                    targets = (node.target,)
                for target in targets:
                    names.update(_assignment_names(target))
    return names


def _scoped_stream_names(tree: ast.AST, aliases: dict[str, str]) -> set[str]:
    """Collect sockets returned by the one DNS-pinned stream factory."""

    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            continue
        value = node.value
        if (
            not isinstance(value, ast.Call)
            or _dotted_name(value.func, aliases).rsplit(".", 1)[-1] != "connect_scoped_stream"
        ):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            names.update(_assignment_names(target))
    return names


def _path_literal_suffix(node: ast.AST) -> tuple[str, ...]:
    """Return only literal path suffix components from ``Path / \"part\"`` AST."""

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return tuple(part for part in node.value.replace("\\", "/").split("/") if part)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return _path_literal_suffix(node.left) + _path_literal_suffix(node.right)
    return ()


def _is_compiled_scope_path(node: ast.AST) -> bool:
    suffix = _path_literal_suffix(node)
    return suffix[-2:] == ("state", "scope.json")


def _compiled_scope_path_names(tree: ast.AST) -> set[str]:
    """Collect local aliases assigned directly to the canonical state file."""

    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            continue
        if not _is_compiled_scope_path(node.value):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            names.update(_assignment_names(target))
    return names


def _is_compiled_scope_path_reference(node: ast.AST, aliases: set[str]) -> bool:
    return _is_compiled_scope_path(node) or (isinstance(node, ast.Name) and node.id in aliases)


def _is_child_environment_values(node: ast.expr, *, known_names: set[str]) -> bool:
    """Accept a ``.values`` mapping only when its receiver is attributable."""

    if not isinstance(node, ast.Attribute) or node.attr != "values":
        return False
    receiver = node.value
    return isinstance(receiver, ast.Name) and receiver.id in known_names


def _is_os_environ(node: ast.AST, aliases: dict[str, str]) -> bool:
    return _dotted_name(node, aliases) == "os.environ"


def _getattr_dotted_name(node: ast.AST, aliases: dict[str, str]) -> str:
    """Resolve a literal ``getattr(module, \"member\")`` without executing it."""

    if not isinstance(node, ast.Call):
        return ""
    if _dotted_name(node.func, aliases) not in {"getattr", "builtins.getattr"}:
        return ""
    if len(node.args) < 2:
        return ""
    member = node.args[1]
    if not isinstance(member, ast.Constant) or not isinstance(member.value, str):
        return ""
    base = _dotted_name(node.args[0], aliases)
    return f"{base}.{member.value}" if base else ""


def _builtins_dictionary_target(node: ast.AST, aliases: dict[str, str]) -> str:
    """Resolve a literal ``builtins.__dict__`` callable lookup."""

    if not isinstance(node, ast.Subscript):
        return ""
    if _dotted_name(node.value, aliases) != "builtins.__dict__":
        return ""
    member = node.slice
    if not isinstance(member, ast.Constant) or not isinstance(member.value, str):
        return ""
    return f"builtins.{member.value}"


def _capability_module_dictionary(node: ast.AST, aliases: dict[str, str]) -> str:
    """Return a known process/network module behind a dictionary object."""

    module = ""
    if isinstance(node, ast.Name):
        canonical = _dotted_name(node, aliases)
        if canonical.startswith(CAPABILITY_MODULE_DICTIONARY_PREFIX):
            module = canonical.removeprefix(CAPABILITY_MODULE_DICTIONARY_PREFIX)
    elif isinstance(node, ast.Call):
        if _dotted_name(node.func, aliases) in {"vars", "builtins.vars"} and len(node.args) == 1:
            module = _dotted_name(node.args[0], aliases)
    elif isinstance(node, ast.Attribute) and node.attr == "__dict__":
        module = _dotted_name(node.value, aliases)
    return module if module in REFLECTIVE_CAPABILITY_MODULES else ""


def _module_dictionary_getter_target(node: ast.AST, aliases: dict[str, str]) -> str:
    """Mark a bound ``.get`` method of a process/network module dictionary."""

    if not isinstance(node, ast.Attribute) or node.attr != "get":
        return ""
    module = _capability_module_dictionary(node.value, aliases)
    return f"{MODULE_DICTIONARY_GETTER_PREFIX}{module}" if module else ""


def _module_dictionary_lookup(node: ast.AST, aliases: dict[str, str]) -> tuple[str, ast.AST | None]:
    """Return a capability module and its dictionary member expression.

    Supported forms are ``mapping[member]``, ``mapping.get(member)``, direct
    ``operator.getitem(mapping, member)``, and a previously bound ``.get``
    method.  Ordinary dictionaries remain outside this bounded lint.
    """

    if isinstance(node, ast.Subscript):
        return _capability_module_dictionary(node.value, aliases), node.slice
    if not isinstance(node, ast.Call):
        return "", None
    target = _dotted_name(node.func, aliases)
    if target in {"dict.get", "builtins.dict.get"} and len(node.args) >= 2:
        return _capability_module_dictionary(node.args[0], aliases), node.args[1]
    if isinstance(node.func, ast.Attribute) and node.func.attr == "get" and node.args:
        return _capability_module_dictionary(node.func.value, aliases), node.args[0]
    if target == "operator.getitem" and len(node.args) >= 2:
        return _capability_module_dictionary(node.args[0], aliases), node.args[1]
    if target.startswith(MODULE_DICTIONARY_GETTER_PREFIX) and node.args:
        return target.removeprefix(MODULE_DICTIONARY_GETTER_PREFIX), node.args[0]
    return "", None


def _module_dictionary_target(node: ast.AST, aliases: dict[str, str]) -> str:
    """Resolve a literal member lookup from a capability module dictionary."""

    module, member = _module_dictionary_lookup(node, aliases)
    if not module or member is None:
        return ""
    if not isinstance(member, ast.Constant) or not isinstance(member.value, str):
        return ""
    return f"{module}.{member.value}"


def _is_computed_module_dictionary_lookup(node: ast.AST, aliases: dict[str, str]) -> bool:
    """Reject a nonliteral member lookup on a process/network module dictionary."""

    module, member = _module_dictionary_lookup(node, aliases)
    if not module or member is None or _module_dictionary_target(node, aliases):
        return False
    return True


def _is_unapproved_module_dictionary_operation(node: ast.AST, aliases: dict[str, str]) -> bool:
    """Reject non-retrieval operations on a process/network module dictionary.

    The approved literal retrieval forms are resolved by
    ``_module_dictionary_lookup``. This intentionally blocks every other
    direct, bound, or unbound dictionary operation for known capability modules
    rather than trying to enumerate new callable-exposure methods.
    """

    if isinstance(node, ast.Attribute):
        return node.attr != "get" and bool(_capability_module_dictionary(node.value, aliases))
    if not isinstance(node, ast.Call):
        return False
    target = _dotted_name(node.func, aliases)
    if target in {"dict.get", "builtins.dict.get"}:
        return False
    if target in {"dict", "builtins.dict"} or target.startswith(("dict.", "builtins.dict.")):
        return bool(node.args and _capability_module_dictionary(node.args[0], aliases))
    return False


def _is_capability_module_dictionary_getattr(node: ast.AST, aliases: dict[str, str]) -> bool:
    """Reject reflective method acquisition from a capability module dictionary."""

    return (
        isinstance(node, ast.Call)
        and _protected_builtin_call_target(node.func, aliases) in {"getattr", "builtins.getattr"}
        and bool(node.args)
        and bool(_capability_module_dictionary(node.args[0], aliases))
    )


def _protected_builtin_call_target(node: ast.AST, aliases: dict[str, str]) -> str:
    """Resolve direct and reflected builtins used as static-policy selectors."""

    return (
        _dotted_name(node, aliases)
        or _builtins_dictionary_target(node, aliases)
        or _module_dictionary_target(node, aliases)
    )


def _static_string_value(node: ast.AST, bindings: dict[str, str]) -> str | None:
    """Return a demonstrably static string without evaluating source code."""

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return bindings.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_string_value(node.left, bindings)
        right = _static_string_value(node.right, bindings)
        if left is not None and right is not None:
            return left + right
        return None
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                rendered = _static_string_value(value.value, bindings)
                if rendered is None:
                    return None
                parts.append(rendered)
            else:
                return None
        return "".join(parts)
    return None


def _static_string_bindings(tree: ast.AST) -> dict[str, str]:
    """Resolve simple source-local names used as dynamic module arguments.

    This is intentionally not a general data-flow engine.  It handles only
    exact name assignments whose expression can be proved to produce a string;
    anything else remains unresolved and is rejected at a dynamic-import
    boundary.  The conservative fallback prevents a branch, callback, or
    runtime input from turning into unreviewed process authority.
    """

    assignments: dict[str, list[ast.AST | None]] = {}

    def record(names: set[str], value: ast.AST | None) -> None:
        for name in names:
            assignments.setdefault(name, []).append(value)

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                record(_assignment_names(target), node.value)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            record(_assignment_names(node.target), node.value)
        elif isinstance(node, ast.NamedExpr):
            record(_assignment_names(node.target), node.value)
        elif isinstance(node, ast.AugAssign):
            # An augmented assignment depends on the runtime prior value, so
            # a previous constant assignment cannot safely survive it.
            record(_assignment_names(node.target), None)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            arguments = node.args
            record(
                {
                    argument.arg
                    for argument in (
                        *arguments.posonlyargs,
                        *arguments.args,
                        *arguments.kwonlyargs,
                    )
                }
                | ({arguments.vararg.arg} if arguments.vararg else set())
                | ({arguments.kwarg.arg} if arguments.kwarg else set()),
                None,
            )

    bindings: dict[str, str] = {}
    # A name remains proved only when *all* observed writes have the same
    # static value.  That intentionally rejects shadowing and branchy source
    # rather than letting an earlier assignment bless a later runtime value.
    # The finite cap also makes maliciously cyclic input deterministic.
    for _ in range(len(assignments) + 1):
        changed = False
        for name, values in assignments.items():
            resolved_values = [_static_string_value(value, bindings) if value is not None else None for value in values]
            if any(value is None for value in resolved_values) or len(set(resolved_values)) != 1:
                continue
            resolved = resolved_values[0]
            if resolved is not None and bindings.get(name) != resolved:
                bindings[name] = resolved
                changed = True
        if not changed:
            break
    return bindings


def _dynamic_import_target(node: ast.Call, aliases: dict[str, str]) -> str:
    """Resolve direct and literal-getattr dynamic import APIs."""

    return (
        _dotted_name(node.func, aliases)
        or _getattr_dotted_name(node.func, aliases)
        or _builtins_dictionary_target(node.func, aliases)
        or _module_dictionary_target(node.func, aliases)
    )


def _dynamic_import_error(node: ast.Call, aliases: dict[str, str], bindings: dict[str, str]) -> str | None:
    """Reject unresolved or process-capable dynamic imports at the boundary."""

    target = _dynamic_import_target(node, aliases)
    if target not in DYNAMIC_IMPORT_CALLS:
        return None
    module = _static_string_value(node.args[0], bindings) if node.args else None
    if module is None:
        return "unresolved dynamic import is forbidden"
    root = module.partition(".")[0]
    if not root or root in DANGEROUS_DYNAMIC_IMPORT_ROOTS:
        return f"process-capable dynamic import is forbidden: {root or '<relative>'}"
    return None


def _process_call_target(node: ast.Call, aliases: dict[str, str]) -> str:
    """Resolve direct and literal-getattr process APIs through import aliases."""

    return (
        _dotted_name(node.func, aliases)
        or _getattr_dotted_name(node.func, aliases)
        or _builtins_dictionary_target(node.func, aliases)
        or _module_dictionary_target(node.func, aliases)
    )


def _is_computed_launch_getattr(node: ast.AST, aliases: dict[str, str]) -> bool:
    """Return whether a launch-capable module has a computed member lookup."""

    if not isinstance(node, ast.Call):
        return False
    if _dotted_name(node.func, aliases) not in {"getattr", "builtins.getattr"}:
        return False
    if not node.args:
        return False
    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
        # Literal lookup is resolved by ``_getattr_dotted_name`` and checked
        # against an exact denylist.  Only a computed member leaves launch
        # authority ambiguous.
        return False
    return _dotted_name(node.args[0], aliases) in DYNAMIC_LAUNCH_LOOKUP_MODULES


def _dynamic_process_getattr(node: ast.Call, aliases: dict[str, str]) -> bool:
    """Reject computed launch/import APIs that cannot be structurally classified."""

    if _dotted_name(node.func, aliases) == "rookery.dynamic-launch-api":
        return True
    return _is_computed_launch_getattr(node.func, aliases)


def _is_subprocess_launch(node: ast.Call, aliases: dict[str, str]) -> bool:
    return _process_call_target(node, aliases) in {
        f"subprocess.{method}" for method in CHILD_ENVIRONMENT_LAUNCH_METHODS
    }


def _is_async_subprocess_launch(node: ast.Call, aliases: dict[str, str]) -> bool:
    return _process_call_target(node, aliases) in {
        f"asyncio.{method}" for method in ASYNC_CHILD_ENVIRONMENT_LAUNCH_METHODS
    }


def _is_unsafe_os_process_api(node: ast.Call, aliases: dict[str, str]) -> bool:
    target = _process_call_target(node, aliases)
    return _is_unsafe_os_process_target(target)


def _is_unsafe_os_process_target(target: str) -> bool:
    if not target.startswith("os."):
        return False
    method = target.rsplit(".", 1)[-1]
    return method in {"popen", "posix_spawn", "posix_spawnp", "system"} or method.startswith(("exec", "spawn"))


def _is_unsafe_pty_process_api(node: ast.Call, aliases: dict[str, str]) -> bool:
    return _process_call_target(node, aliases) == "pty.spawn"


def _process_concurrency_target(node: ast.AST, aliases: dict[str, str]) -> str:
    """Resolve process-backed concurrency constructors and common aliases."""

    callable_node = node.func if isinstance(node, ast.Call) else node
    target = _dotted_name(callable_node, aliases) or _getattr_dotted_name(callable_node, aliases)
    if target in PROCESS_CONCURRENCY_CALLS:
        return target
    if not isinstance(callable_node, ast.Attribute):
        return ""
    if callable_node.attr == "Process":
        base = _dotted_name(callable_node.value, aliases)
        if base in {"multiprocessing", "multiprocessing.context"}:
            return "multiprocessing.Process"
        if (
            isinstance(callable_node.value, ast.Call)
            and _dotted_name(callable_node.value.func, aliases) == "multiprocessing.get_context"
        ):
            return "multiprocessing.Process"
    if callable_node.attr == "Pool":
        base = _dotted_name(callable_node.value, aliases)
        if base in {"multiprocessing", "multiprocessing.pool"}:
            return "multiprocessing.Pool"
        if (
            isinstance(callable_node.value, ast.Call)
            and _dotted_name(callable_node.value.func, aliases) == "multiprocessing.get_context"
        ):
            return "multiprocessing.Pool"
    return ""


def _is_unsafe_process_concurrency(node: ast.Call, aliases: dict[str, str]) -> bool:
    return bool(_process_concurrency_target(node, aliases))


def _is_unsafe_builtin_code_execution(node: ast.Call, aliases: dict[str, str]) -> bool:
    return _process_call_target(node, aliases) in UNSAFE_BUILTIN_CODE_CALLS


def _is_unsafe_callable_target(target: str) -> bool:
    """Classify a directly resolved callable without interpreting source."""

    return (
        _is_unsafe_os_process_target(target)
        or _is_raw_network_callable_target(target)
        or target == "pty.spawn"
        or target
        in {
            *(f"subprocess.{method}" for method in CHILD_ENVIRONMENT_LAUNCH_METHODS),
            *(f"asyncio.{method}" for method in ASYNC_CHILD_ENVIRONMENT_LAUNCH_METHODS),
            *PROCESS_CONCURRENCY_CALLS,
            *UNSAFE_BUILTIN_CODE_CALLS,
        }
    )


def _operator_callable_alias_target(node: ast.Call, aliases: dict[str, str]) -> str:
    """Resolve direct ``operator`` getter/caller handoffs to known modules.

    It intentionally handles only the literal factory followed immediately by
    a known module object.  Chained, data-driven, and reflective constructs
    are outside this regression lint rather than being misrepresented as a
    general de-obfuscator.
    """

    factory = node.func
    if not isinstance(factory, ast.Call) or not factory.args or not node.args:
        return ""
    factory_target = _process_call_target(factory, aliases)
    if factory_target not in {"operator.attrgetter", "operator.methodcaller"}:
        return ""
    member = factory.args[0]
    if not isinstance(member, ast.Constant) or not isinstance(member.value, str):
        return ""
    base = _dotted_name(node.args[0], aliases)
    return f"{base}.{member.value}" if base else ""


def _is_unsafe_operator_callable_alias(node: ast.Call, aliases: dict[str, str]) -> bool:
    target = _operator_callable_alias_target(node, aliases)
    return _is_unsafe_callable_target(target) or bool(_process_concurrency_target(node, aliases))


def _is_unsafe_functools_callable_alias(node: ast.Call, aliases: dict[str, str]) -> bool:
    """Reject partial application that conceals a process or evaluator call.

    This intentionally covers only the directly inspectable ``partial``
    shape.  Arbitrary factories, reflection, and bytecode construction remain
    outside a deterministic AST gate; they are not represented as solved.
    """

    if _process_call_target(node, aliases) != "functools.partial" or not node.args:
        return False
    candidate = node.args[0]
    if _is_computed_launch_getattr(candidate, aliases):
        return True
    target = _dotted_name(candidate, aliases) or _getattr_dotted_name(candidate, aliases)
    return _is_unsafe_callable_target(target) or bool(_process_concurrency_target(candidate, aliases))


def _network_client_constructor_target(node: ast.AST, aliases: dict[str, str]) -> str:
    """Label only direct raw client objects so their later methods stay visible."""

    if not isinstance(node, ast.Call):
        return ""
    target = _process_call_target(node, aliases)
    if target == "socket.socket":
        return "rookery.raw-socket"
    if target in RAW_HTTP_CLIENT_TARGETS:
        return "rookery.raw-http-client"
    if target in GENERIC_URLOPEN_TARGETS:
        return "rookery.generic-urllib-opener"
    return ""


def _socket_instance_getattr_target(node: ast.AST, aliases: dict[str, str]) -> str:
    """Resolve direct literal lookup from a raw ``socket.socket()`` instance."""

    if not isinstance(node, ast.Call) or len(node.args) < 2:
        return ""
    if _dotted_name(node.func, aliases) not in {"getattr", "builtins.getattr"}:
        return ""
    member = node.args[1]
    if not isinstance(member, ast.Constant) or not isinstance(member.value, str):
        return ""
    receiver = node.args[0]
    if isinstance(receiver, ast.Call) and _process_call_target(receiver, aliases) == "socket.socket":
        return f"rookery.raw-socket.{member.value}"
    return ""


def _is_raw_urllib_transfer(node: ast.Call, aliases: dict[str, str]) -> bool:
    return _process_call_target(node, aliases) in RAW_URLLIB_TRANSFER_TARGETS


def _is_generic_urllib_opener(node: ast.Call, aliases: dict[str, str]) -> bool:
    target = _process_call_target(node, aliases)
    return target in GENERIC_URLOPEN_TARGETS or target == "rookery.generic-urllib-opener.open"


def _is_socket_dns_lookup(node: ast.Call, aliases: dict[str, str]) -> bool:
    return _process_call_target(node, aliases) in RAW_SOCKET_DNS_TARGETS


def _is_unpinned_socket_connection(node: ast.Call, aliases: dict[str, str]) -> bool:
    target = _process_call_target(node, aliases)
    if target in {
        "socket.create_connection",
        "socket.socket.connect",
        "socket.socket.connect_ex",
        "rookery.raw-socket.connect",
        "rookery.raw-socket.connect_ex",
    }:
        return True
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr in {"connect", "connect_ex"}
        and isinstance(node.func.value, ast.Call)
        and _process_call_target(node.func.value, aliases) == "socket.socket"
    )


def _is_raw_socket_datagram_send(node: ast.Call, aliases: dict[str, str]) -> bool:
    target = _process_call_target(node, aliases)
    if target in {"socket.socket.sendto", "rookery.raw-socket.sendto"}:
        return True
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "sendto"
        and isinstance(node.func.value, ast.Call)
        and _process_call_target(node.func.value, aliases) == "socket.socket"
    )


def _is_raw_http_client_use(node: ast.Call, aliases: dict[str, str]) -> bool:
    target = _process_call_target(node, aliases)
    if target in RAW_HTTP_CLIENT_TARGETS or target in {
        "rookery.raw-http-client.connect",
        "rookery.raw-http-client.request",
    }:
        return True
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr in {"connect", "request"}
        and isinstance(node.func.value, ast.Call)
        and _process_call_target(node.func.value, aliases) in RAW_HTTP_CLIENT_TARGETS
    )


def _is_raw_network_callable_target(target: str) -> bool:
    return target in {
        *RAW_URLLIB_TRANSFER_TARGETS,
        *RAW_HTTP_CLIENT_TARGETS,
        *RAW_SOCKET_DNS_TARGETS,
        *GENERIC_URLOPEN_TARGETS,
        "socket.create_connection",
        "socket.socket.connect",
        "socket.socket.connect_ex",
        "socket.socket.sendto",
        "websocket.create_connection",
        "rookery.raw-socket.connect",
        "rookery.raw-socket.connect_ex",
        "rookery.raw-socket.sendto",
        "rookery.raw-http-client.connect",
        "rookery.raw-http-client.request",
        "rookery.generic-urllib-opener.open",
    }


def _is_unpinned_websocket_connection(node: ast.Call, aliases: dict[str, str], scoped_streams: set[str]) -> bool:
    if _process_call_target(node, aliases) != "websocket.create_connection":
        return False
    socket_values = [keyword.value for keyword in node.keywords if keyword.arg == "socket"]
    return not (
        len(socket_values) == 1 and isinstance(socket_values[0], ast.Name) and socket_values[0].id in scoped_streams
    )


def _literal_argv_executable(node: ast.AST) -> str | None:
    """Return an argv[0] literal without resolving variables or shell text."""

    if not isinstance(node, (ast.List, ast.Tuple)) or not node.elts:
        return None
    executable = node.elts[0]
    if not isinstance(executable, ast.Constant) or not isinstance(executable.value, str):
        return None
    return executable.value.rsplit("/", 1)[-1].casefold()


def _is_raw_netcat_helper(node: ast.Call, aliases: dict[str, str]) -> bool:
    """Reject literal netcat launches outside the DNS-pinned command planner."""

    target = _process_call_target(node, aliases)
    if target not in {
        *(f"subprocess.{method}" for method in CHILD_ENVIRONMENT_LAUNCH_METHODS),
        "run_bounded_argv",
        "rookery.portable.adapters.run_bounded_argv",
    }:
        return False
    return bool(node.args) and _literal_argv_executable(node.args[0]) in NETCAT_EXECUTABLES


def _is_direct_compiled_scope_read(node: ast.Call, aliases: dict[str, str], scope_paths: set[str]) -> bool:
    """Recognise an executable read of ``state/scope.json`` by path or alias."""

    target = _process_call_target(node, aliases)
    if target in {"open", "builtins.open", "os.open"}:
        return bool(node.args) and _is_compiled_scope_path_reference(node.args[0], scope_paths)
    if target == "load_json" or target.endswith(".load_json"):
        return bool(node.args) and _is_compiled_scope_path_reference(node.args[0], scope_paths)
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr in {"open", "read_bytes", "read_text"}
        and _is_compiled_scope_path_reference(node.func.value, scope_paths)
    )


def _startup_entrypoint_errors(relative: str, raw: bytes) -> list[str]:
    """Require isolated Python startup for the small public/trusted boundary."""

    if relative not in TRUSTED_STARTUP_ENTRYPOINTS:
        return []
    if PYTHON_SHEBANG.match(raw):
        if not ISOLATED_PYTHON_SHEBANG.match(raw):
            return ["trusted Python entrypoint must use an isolated -I -S shebang: " + relative]
        return []
    if ISOLATED_SHELL_PYTHON_BOOTSTRAP.search(raw):
        return []
    # ``go`` and ``run-codex`` delegate only to the checked wrappers; they do
    # not themselves start Python.  Keep that distinction enforceable: a
    # future direct Python call in either script must be isolated, too.
    if relative in {"go", "run-codex"}:
        if SHELL_PYTHON_INVOCATION.search(raw):
            return ["trusted Python entrypoint must start Python with -I -S: " + relative]
        return []
    return ["trusted Python entrypoint must start Python with -I -S: " + relative]


def _enclosing_function(node: ast.AST) -> str:
    function = _enclosing_function_node(node)
    return function.name if function is not None else ""


def _enclosing_function_node(
    node: ast.AST,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    current = getattr(node, "parent", None)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current
        current = getattr(current, "parent", None)
    return None


def _function_name_assignments(function: ast.FunctionDef | ast.AsyncFunctionDef, name: str) -> list[ast.AST]:
    """Return direct assignments to a name, excluding nested functions."""

    assignments: list[ast.AST] = []
    for node in ast.walk(function):
        if _enclosing_function_node(node) is not function:
            continue
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in node.targets
        ):
            assignments.append(node)
        elif (
            isinstance(node, (ast.AnnAssign, ast.NamedExpr))
            and isinstance(node.target, ast.Name)
            and node.target.id == name
        ):
            assignments.append(node)
    return assignments


def _single_exact_assignment(function: ast.FunctionDef | ast.AsyncFunctionDef, name: str) -> ast.AST | None:
    assignments = _function_name_assignments(function, name)
    return assignments[0] if len(assignments) == 1 else None


def _ast_assignment_value(node: ast.AST) -> ast.AST | None:
    return node.value if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) else None


def _is_name(node: ast.AST, name: str) -> bool:
    return isinstance(node, ast.Name) and node.id == name


def _is_exact_call(
    node: ast.AST | None,
    name: str,
    arguments: tuple[str, ...],
    keywords: tuple[tuple[str, str], ...] = (),
) -> bool:
    """Check a non-aliased, positional/keyword call without broad dataflow."""

    if not isinstance(node, ast.Call) or not _is_name(node.func, name):
        return False
    if len(node.args) != len(arguments) or any(
        not _is_name(argument, expected) for argument, expected in zip(node.args, arguments, strict=True)
    ):
        return False
    return len(node.keywords) == len(keywords) and all(
        keyword.arg == expected_name and _is_name(keyword.value, expected_value)
        for keyword, (expected_name, expected_value) in zip(node.keywords, keywords, strict=True)
    )


def _is_verified_procfd_executable(value: ast.AST | None, descriptor_name: str) -> bool:
    """Recognise only the fixed proc-fd path used by the verified launcher."""

    if not isinstance(value, ast.JoinedStr) or len(value.values) != 2:
        return False
    prefix, descriptor = value.values
    return (
        isinstance(prefix, ast.Constant)
        and prefix.value == "/proc/self/fd/"
        and isinstance(descriptor, ast.FormattedValue)
        and _is_name(descriptor.value, descriptor_name)
        and descriptor.conversion == -1
        and descriptor.format_spec is None
    )


def _is_exact_child_environment_copy(node: ast.AST, known_child_environments: set[str]) -> bool:
    """Allow the one exec API's defensive copy of a proved child mapping."""

    return (
        isinstance(node, ast.Call)
        and _is_name(node.func, "dict")
        and len(node.args) == 1
        and not node.keywords
        and _is_child_environment_values(node.args[0], known_names=known_child_environments)
    )


def _is_exact_verified_codex_exec_replacement(
    node: ast.Call,
    relative: str,
    known_child_environments: set[str],
) -> bool:
    """Allow only the verified final Codex process replacement.

    ``execve`` normally bypasses the bounded subprocess contract, so this
    exception is deliberately structural: the executable must be the open,
    verified descriptor's proc-fd path; argv must start from that exact path;
    and the mapping must be a defensive copy of an attributable
    ``ChildEnvironment.values``.  Any alias, alternate function, ambient
    mapping, or dynamic executable continues through the ordinary deny path.
    """

    if (
        relative != "lib/rookery/portable/environment.py"
        or not (isinstance(node.func, ast.Attribute) and _is_name(node.func.value, "os") and node.func.attr == "execve")
        or node.keywords
        or len(node.args) != 3
        or not _is_name(node.args[0], "executable")
        or not _is_name(node.args[1], "final_arguments")
        or not _is_exact_child_environment_copy(node.args[2], known_child_environments)
    ):
        return False
    function = _enclosing_function_node(node)
    if function is None or function.name != "codex_launcher_main":
        return False

    descriptor = _single_exact_assignment(function, "descriptor")
    executable = _single_exact_assignment(function, "executable")
    arguments = _single_exact_assignment(function, "final_arguments")
    child = _single_exact_assignment(function, "child")
    binding = _single_exact_assignment(function, "binding")
    if not (
        _is_exact_call(
            _ast_assignment_value(descriptor),
            "_open_verified_codex_descriptor",
            ("binding",),
        )
        and _is_verified_procfd_executable(_ast_assignment_value(executable), "descriptor")
        and isinstance(_ast_assignment_value(arguments), ast.List)
        and len(_ast_assignment_value(arguments).elts) == 1
        and _is_name(_ast_assignment_value(arguments).elts[0], "executable")
        and _is_exact_call(
            _ast_assignment_value(child),
            "codex_launcher_environment",
            ("workspace",),
            (("parent", "parent"),),
        )
        and _is_exact_call(
            _ast_assignment_value(binding),
            "_verify_exec_binding",
            ("workspace", "child"),
            (("parent", "parent"),),
        )
    ):
        return False
    return True


class _AmbientEnvironmentVisitor(ast.NodeVisitor):
    """Find parent-environment authority outside the central resolver."""

    def __init__(self, relative: str, aliases: dict[str, str]) -> None:
        self.relative = relative
        self.aliases = aliases
        self.errors: list[str] = []
        self._functions: list[str] = []

    def _allowed_bootstrap(self, node: ast.AST) -> bool:
        return (
            (self.relative, self._functions[-1] if self._functions else "") == ROOKERY_ROOT_BOOTSTRAP
            and isinstance(node, ast.Call)
            and _dotted_name(node.func, self.aliases) == "os.environ.get"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "ROOKERY_ROOT"
        )

    def _error(self, message: str, node: ast.AST) -> None:
        self.errors.append(f"{message}: {self.relative}:{node.lineno}")

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._functions.append(node.name)
        self.generic_visit(node)
        self._functions.pop()

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function

    def visit_Call(self, node: ast.Call) -> None:
        dotted = _dotted_name(node.func, self.aliases)
        if dotted in AMBIENT_ENVIRONMENT_APIS:
            self._error("ambient environment API is forbidden", node)
        elif dotted.startswith("os.environ."):
            if not self._allowed_bootstrap(node):
                if dotted in {"os.environ.copy", "os.environ.update"}:
                    self._error("whole ambient environment mapping is forbidden", node)
                else:
                    self._error("ambient environment access is forbidden", node)
        elif (
            isinstance(node.func, ast.Name)
            and node.func.id == "dict"
            and len(node.args) == 1
            and _is_os_environ(node.args[0], self.aliases)
        ):
            self._error("whole ambient environment mapping is forbidden", node)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if _is_os_environ(node.value, self.aliases):
            self._error("ambient environment access is forbidden", node)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # A bare ``os.environ`` passed as data does not necessarily produce a
        # call or subscription.  Record it once, but avoid a duplicate beside
        # a recognised ``.get``/``.copy`` call above.
        dotted = _dotted_name(node, self.aliases)
        parent = getattr(node, "parent", None)
        if dotted in AMBIENT_ENVIRONMENT_APIS:
            if not (isinstance(parent, ast.Call) and parent.func is node):
                self._error("ambient environment API is forbidden", node)
        elif _is_os_environ(node, self.aliases):
            parent_is_environment_method = isinstance(getattr(node, "parent", None), ast.Attribute)
            parent_call = getattr(parent, "parent", None)
            if not (parent_is_environment_method and isinstance(parent_call, ast.Call) and parent_call.func is parent):
                self._error("ambient environment access is forbidden", node)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        """Catch aliases retained for delayed ambient access or map copying."""

        dotted = _dotted_name(node, self.aliases)
        parent = getattr(node, "parent", None)
        if dotted in AMBIENT_ENVIRONMENT_APIS:
            if not (isinstance(parent, ast.Call) and parent.func is node):
                self._error("ambient environment API is forbidden", node)
        elif dotted == "os.environ":
            parent_is_attribute = isinstance(parent, ast.Attribute) and parent.value is node
            parent_is_dict = (
                isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name) and parent.func.id == "dict"
            )
            if not parent_is_attribute and not parent_is_dict:
                self._error("ambient environment access is forbidden", node)
        self.generic_visit(node)


def _attach_parents(tree: ast.AST) -> None:
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]


def _is_duplicate_dotenv_reader(node: ast.AST) -> bool:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    name = node.name.casefold()
    if not re.search(r"(?:read|parse|load).*env|env.*(?:read|parse|load)", name):
        return False
    body = list(ast.walk(node))
    mentions_dotenv = any(
        isinstance(item, ast.Constant) and isinstance(item.value, str) and item.value in {".env", "prepared.env"}
        for item in body
    )
    reads_file = any(
        isinstance(item, ast.Call)
        and isinstance(item.func, ast.Attribute)
        and item.func.attr in {"open", "read_text", "read_bytes"}
        for item in body
    )
    # ``read_env`` that only delegates to the central parser is not duplicate
    # grammar.  A local reader is one that owns file I/O, or that hard-codes a
    # dotenv filename for another parser.  This deliberately catches generic
    # helpers such as ``parse_env_file(path)`` as well as ``read_env()``.
    return reads_file or mentions_dotenv


def _static_python_errors(tree: ast.AST, relative: str) -> list[str]:
    """Return deterministic, value-free launch/environment policy findings."""

    _attach_parents(tree)
    aliases = _import_aliases(tree)
    known_child_environments = _child_environment_names(tree, aliases)
    known_scoped_streams = _scoped_stream_names(tree, aliases)
    compiled_scope_paths = _compiled_scope_path_names(tree)
    static_strings = _static_string_bindings(tree)
    errors: list[str] = []
    if relative != "lib/rookery/portable/environment.py":
        environment_visitor = _AmbientEnvironmentVisitor(relative, aliases)
        environment_visitor.visit(tree)
        errors.extend(environment_visitor.errors)

    for node in ast.walk(tree):
        if (
            _is_duplicate_dotenv_reader(node)
            and relative != "lib/rookery/portable/environment.py"
            and not (
                relative == "lib/rookery/portable/validator.py"
                and getattr(node, "name", "") == "_is_duplicate_dotenv_reader"
            )
        ):
            errors.append(f"duplicate dotenv reader is forbidden: {relative}:{node.lineno}")
        if isinstance(node, ast.Call):
            dynamic_import_error = _dynamic_import_error(node, aliases, static_strings)
            if dynamic_import_error:
                errors.append(f"{dynamic_import_error}: {relative}:{node.lineno}")
        if isinstance(node, ast.Call) and _dynamic_process_getattr(node, aliases):
            errors.append(f"computed process API lookup is forbidden: {relative}:{node.lineno}")
        if _is_computed_module_dictionary_lookup(node, aliases):
            errors.append(f"computed module capability lookup is forbidden: {relative}:{node.lineno}")
        if _is_unapproved_module_dictionary_operation(node, aliases):
            errors.append(f"capability module dictionary operation is forbidden: {relative}:{node.lineno}")
        if _is_capability_module_dictionary_getattr(node, aliases):
            errors.append(f"capability module dictionary getattr is forbidden: {relative}:{node.lineno}")
        if isinstance(node, ast.Call) and _is_unsafe_process_concurrency(node, aliases):
            errors.append(f"process-backed concurrency launch is forbidden: {relative}:{node.lineno}")
        if isinstance(node, ast.Call) and _is_unsafe_builtin_code_execution(node, aliases):
            errors.append(f"builtins code execution is forbidden: {relative}:{node.lineno}")
        if isinstance(node, ast.Call) and _is_unsafe_operator_callable_alias(node, aliases):
            errors.append(f"unsafe operator callable alias is forbidden: {relative}:{node.lineno}")
        if isinstance(node, ast.Call) and _is_unsafe_functools_callable_alias(node, aliases):
            errors.append(f"unsafe functools callable alias is forbidden: {relative}:{node.lineno}")
        if (
            isinstance(node, ast.Call)
            and (_is_subprocess_launch(node, aliases) or _is_async_subprocess_launch(node, aliases))
            and (
                relative,
                _enclosing_function(node),
            )
            != INTERNAL_BOUNDED_SPAWN
        ):
            environment = next(
                (keyword.value for keyword in node.keywords if keyword.arg == "env"),
                None,
            )
            if environment is None or (isinstance(environment, ast.Constant) and environment.value is None):
                errors.append(f"child environment launch requires ChildEnvironment.values: {relative}:{node.lineno}")
            elif not _is_child_environment_values(environment, known_names=known_child_environments):
                errors.append(f"child environment launch forbids a whole environment mapping: {relative}:{node.lineno}")
        if isinstance(node, ast.Call) and _is_async_subprocess_launch(node, aliases):
            # Asyncio exposes a second process-launch implementation outside
            # the audited synchronous ChildEnvironment boundary.  There is no
            # shipped asynchronous child owner, so both shell and exec forms
            # fail closed instead of becoming an unreviewed exception.
            errors.append(f"asyncio subprocess launch is forbidden: {relative}:{node.lineno}")
            if _process_call_target(node, aliases) == "asyncio.create_subprocess_shell":
                errors.append(f"asyncio shell process launch is forbidden: {relative}:{node.lineno}")
        if (
            isinstance(node, ast.Call)
            and _is_unsafe_os_process_api(node, aliases)
            and not _is_exact_verified_codex_exec_replacement(node, relative, known_child_environments)
        ):
            errors.append(f"unsafe os process API is forbidden: {relative}:{node.lineno}")
        if isinstance(node, ast.Call) and _is_unsafe_pty_process_api(node, aliases):
            errors.append(f"unsafe pty process API is forbidden: {relative}:{node.lineno}")
        if isinstance(node, ast.Call) and _is_socket_dns_lookup(node, aliases) and relative != SCOPED_TRANSPORT_MODULE:
            errors.append(f"raw socket DNS lookup is forbidden outside DNS-pinned transport: {relative}:{node.lineno}")
        if (
            isinstance(node, ast.Call)
            and _is_unpinned_socket_connection(node, aliases)
            and relative != SCOPED_TRANSPORT_MODULE
        ):
            errors.append(
                f"unpinned socket connection is forbidden outside DNS-pinned transport: {relative}:{node.lineno}"
            )
        if (
            isinstance(node, ast.Call)
            and _is_unpinned_websocket_connection(node, aliases, known_scoped_streams)
            and relative != SCOPED_TRANSPORT_MODULE
        ):
            errors.append(
                f"unpinned websocket connection is forbidden outside DNS-pinned transport: {relative}:{node.lineno}"
            )
        if (
            isinstance(node, ast.Call)
            and _is_generic_urllib_opener(node, aliases)
            and relative != SCOPED_TRANSPORT_MODULE
        ):
            errors.append(f"generic urllib opener is forbidden outside DNS-pinned transport: {relative}:{node.lineno}")
        if isinstance(node, ast.Call) and _is_raw_netcat_helper(node, aliases):
            errors.append(f"raw netcat helper is forbidden outside DNS-pinned transport: {relative}:{node.lineno}")
        if (
            isinstance(node, ast.Call)
            and _is_direct_compiled_scope_read(node, aliases, compiled_scope_paths)
            and relative not in CANONICAL_SCOPE_READ_ALLOWLIST
        ):
            errors.append(
                f"direct state/scope.json read is forbidden outside canonical scope loader: {relative}:{node.lineno}"
            )
        if (
            isinstance(node, ast.Call)
            and _is_raw_urllib_transfer(node, aliases)
            and relative not in RAW_URLOPEN_ALLOWLIST
        ):
            target = _process_call_target(node, aliases)
            errors.append(
                f"raw urllib transfer is forbidden outside DNS-pinned transport: {target}: {relative}:{node.lineno}"
            )
        if (
            isinstance(node, ast.Call)
            and _is_raw_http_client_use(node, aliases)
            and relative != SCOPED_TRANSPORT_MODULE
        ):
            errors.append(f"raw HTTP client is forbidden outside DNS-pinned transport: {relative}:{node.lineno}")
        if (
            isinstance(node, ast.Call)
            and _is_raw_socket_datagram_send(node, aliases)
            and relative != SCOPED_TRANSPORT_MODULE
        ):
            errors.append(
                f"raw socket datagram send is forbidden outside DNS-pinned transport: {relative}:{node.lineno}"
            )
        if (
            isinstance(node, (ast.Name, ast.Attribute))
            and _is_raw_network_callable_target(_dotted_name(node, aliases))
            and relative != SCOPED_TRANSPORT_MODULE
        ):
            parent = getattr(node, "parent", None)
            if not (isinstance(parent, ast.Call) and parent.func is node):
                errors.append(
                    f"raw network callable reference is forbidden outside DNS-pinned transport: {relative}:{node.lineno}"
                )
        if (
            isinstance(node, ast.Call)
            and _is_raw_network_callable_target(_socket_instance_getattr_target(node, aliases))
            and relative != SCOPED_TRANSPORT_MODULE
        ):
            errors.append(
                f"raw network callable reference is forbidden outside DNS-pinned transport: {relative}:{node.lineno}"
            )
    return sorted(set(errors))


def _child_environment_launch_errors(tree: ast.AST, relative: str) -> list[str]:
    """Compatibility wrapper retained for focused launch-policy tests."""

    return _static_python_errors(tree, relative)


def _read_static_python_source(path: Path, *, expected: os.stat_result | None = None) -> bytes:
    """Read one regular source without following a replacement symlink."""

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        initial = os.fstat(descriptor)
        if not stat.S_ISREG(initial.st_mode):
            raise OSError("not a regular file")
        if expected is not None and (initial.st_dev, initial.st_ino) != (
            expected.st_dev,
            expected.st_ino,
        ):
            raise OSError("source changed before static scan")
        if initial.st_size > STATIC_SOURCE_MAX_BYTES:
            raise OSError("source exceeds static scan limit")
        chunks: list[bytes] = []
        remaining = STATIC_SOURCE_MAX_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        final = os.fstat(descriptor)
        if (initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns) != (
            final.st_dev,
            final.st_ino,
            final.st_size,
            final.st_mtime_ns,
        ):
            raise OSError("source changed during static scan")
        if len(data) > STATIC_SOURCE_MAX_BYTES:
            raise OSError("source exceeds static scan limit")
        return data
    finally:
        os.close(descriptor)


def _iter_shipped_python_sources(root: Path, errors: list[str]) -> Iterator[tuple[str, bytes]]:
    """Yield every regular shipped Python module or Python-shebang helper.

    Symlinks and nonregular ``.py`` paths are findings rather than silently
    skipped.  They cannot be safely interpreted as a shipped source boundary.
    Extensionless entries are read only after regular/no-follow validation.
    """

    seen: set[str] = set()
    candidates: list[Path] = []
    for relative_root in SHIPPED_PYTHON_SOURCE_ROOTS:
        base = root / relative_root
        if not base.is_dir() or base.is_symlink():
            continue
        candidates.extend(base.rglob("*"))
    for path in sorted(candidates, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if relative in seen or path.is_dir():
            continue
        seen.add(relative)
        parts = Path(relative).parts
        executable_location = parts[:1] == ("bin",) or (
            len(parts) >= 3 and parts[0] in {"adapters", "extensions"} and parts[2] == "bin"
        )
        suffix_is_python = path.suffix.casefold() == ".py"
        extensionless_entrypoint = executable_location and not path.suffix
        static_candidate = suffix_is_python or extensionless_entrypoint
        try:
            info = path.lstat()
        except OSError as exc:
            if static_candidate:
                errors.append(f"static Python source is inaccessible: {relative}: {exc.__class__.__name__}")
            continue
        if stat.S_ISLNK(info.st_mode):
            if static_candidate:
                errors.append(f"static Python source must not be a symlink: {relative}")
            continue
        if not stat.S_ISREG(info.st_mode):
            if static_candidate:
                errors.append(f"static Python source must be a regular file: {relative}")
            continue
        try:
            raw = _read_static_python_source(path, expected=info)
        except OSError as exc:
            if static_candidate:
                errors.append(f"static Python source is unreadable: {relative}: {exc}")
            continue
        if suffix_is_python or PYTHON_SHEBANG.match(raw):
            yield relative, raw


def _validate_child_environment_launches(root: Path, errors: list[str]) -> None:
    """Scan every shipped Python launch/configuration surface before release."""

    for relative, raw in _iter_shipped_python_sources(root, errors):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            errors.append(f"static Python source decode failed: {relative}: {exc.start}")
            continue
        try:
            tree = ast.parse(text, filename=relative)
        except SyntaxError as exc:
            errors.append(f"static Python source syntax failed: {relative}:{exc.lineno or 0}: {exc.msg}")
            continue
        errors.extend(_static_python_errors(tree, relative))


def _validate_startup_entrypoints(root: Path, errors: list[str]) -> None:
    """Scan the exact public/trusted launchers without trusting path aliases."""

    for relative in TRUSTED_STARTUP_ENTRYPOINTS:
        path = root / relative
        try:
            info = path.lstat()
        except OSError as exc:
            errors.append(f"trusted startup entrypoint is inaccessible: {relative}: {exc.__class__.__name__}")
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            errors.append(f"trusted startup entrypoint must be a regular file: {relative}")
            continue
        try:
            raw = _read_static_python_source(path, expected=info)
        except OSError as exc:
            errors.append(f"trusted startup entrypoint is unreadable: {relative}: {exc}")
            continue
        errors.extend(_startup_entrypoint_errors(relative, raw))


def _validate_core_bin_python_shebangs(root: Path, errors: list[str]) -> None:
    """Apply the isolated-startup contract to all core Python shebang helpers."""

    for relative, raw in _iter_shipped_python_sources(root, errors):
        errors.extend(_core_bin_python_shebang_errors(relative, raw))


def _validate_adapter_extension_python_shebangs(root: Path, errors: list[str]) -> None:
    """Apply the isolated-startup contract to optional Rookery helpers."""

    for relative, raw in _iter_shipped_python_sources(root, errors):
        errors.extend(_adapter_extension_python_shebang_errors(relative, raw))
        errors.extend(_adapter_extension_script_root_errors(relative, raw))


def _iter_descriptor_ids(root: Path, kind: str) -> list[str]:
    descriptor_name = "adapter.json" if kind == "adapters" else "extension.json"
    ids: list[str] = []
    base = root / kind
    if not base.exists():
        return ids
    for descriptor in sorted(base.glob(f"*/{descriptor_name}")):
        data = load_json(descriptor, {})
        if isinstance(data, dict) and data.get("id"):
            ids.append(str(data["id"]))
    return ids


def _iter_contract_files(root: Path, release: dict[str, Any]) -> Iterable[Path]:
    seen: set[Path] = set()
    for rel in release.get("generic_contract_paths", []):
        path = root / str(rel)
        if path.is_file():
            seen.add(path)
        elif path.is_dir():
            for candidate in path.rglob("*"):
                if candidate.is_file():
                    seen.add(candidate)
    for path in sorted(seen):
        yield path


def _text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _is_allowed_secret_example(value: str) -> bool:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    return not value or value.lower() in ALLOWED_SECRET_EXAMPLES or value.startswith("${")


def _is_operational_configuration_key(key: str) -> bool:
    """Keep acknowledgement and tuning keys distinct from credential values."""

    return bool(set(key.upper().split("_")) & OPERATIONAL_CONFIGURATION_SEGMENTS)


def _is_credential_key(key: str) -> bool:
    """Recognize credential-bearing segments without substring false positives."""

    segments = tuple(key.upper().split("_"))
    if _is_operational_configuration_key(key):
        return False
    if any(segment in SENSITIVE_CREDENTIAL_SEGMENTS for segment in segments):
        return True
    return any(
        segment in {"ACCESS", "API", "PRIVATE"}
        and index + 1 < len(segments)
        and segments[index + 1] in {"ID", "KEY", "SECRET", "TOKEN"}
        for index, segment in enumerate(segments)
    ) or bool(
        {
            "ACCESSKEY",
            "AUTHTICKET",
            "CFCLEARANCE",
            "JSESSIONID",
            "PHPSESSID",
            "SESSIONCOOKIE",
        }
        & set(segments)
    )


def _is_environment_or_default_file(path: Path) -> bool:
    """Identify bounded, shipped configuration defaults without scanning code."""

    name = path.name.lower()
    return (
        name in {".env", ".env.example", "env.example"}
        or name.endswith(".env")
        or name.endswith(".env.example")
        or name.startswith(("default.", "defaults."))
        or ".default." in name
        or ".defaults." in name
    )


def _contains_credential_material(text: str) -> bool:
    """Recognize credentials by assignment, URL, or PEM block without exposing values.

    The release gate deliberately errs on the side of stopping a build when a
    shipped default contains a credential-like assignment. It accepts only
    empty or explicit placeholder values for credential-named settings.
    """

    if CREDENTIALED_URL.search(text) or PRIVATE_KEY_BLOCK.search(text):
        return True

    for match in ENV_ASSIGNMENT.finditer(text):
        key, value = match.groups()
        if _is_allowed_secret_example(value):
            continue
        if _is_credential_key(key) or CREDENTIAL_VALUE.search(value):
            return True
    return False


def _environment_assignments(text: str) -> list[tuple[str, str]]:
    return [(match.group(1), match.group(2)) for match in ENV_ASSIGNMENT.finditer(text)]


def _assignment_value(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _is_names_only_environment_array(value: str) -> bool:
    """Accept bounded exact-name arrays without inspecting any credential value."""

    try:
        parsed = json.loads(_assignment_value(value))
    except json.JSONDecodeError:
        return False
    if not isinstance(parsed, list) or len(parsed) > 256:
        return False
    if any(
        not isinstance(item, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", item) or item == "ROOKERY_OWNER_TOKEN"
        for item in parsed
    ):
        return False
    return len({item.casefold() for item in parsed}) == len(parsed)


def _adapter_catalog_environment_keys(root: Path, errors: list[str]) -> frozenset[str]:
    """Return the reviewed union of adapter-specific root-template names.

    The public root template is an inert catalogue so an operator can configure
    any selected adapter in one private `.env`. Descriptors remain the source
    of truth: malformed descriptor schema is reported rather than making an
    arbitrary template assignment valid.
    """

    core_names = {field.name for field in CORE_EVENT_ENVIRONMENT_SCHEMA}
    descriptor_ids: set[str] = set()
    descriptor_names: set[str] = set()
    for descriptor in sorted((root / "adapters").glob("*/adapter.json")):
        adapter_id = descriptor.parent.name
        descriptor_ids.add(adapter_id)
        try:
            descriptor_names.update(event_environment_names(root, adapter_id) - core_names)
        except ValueError:
            errors.append(
                "adapter environment schema unavailable for release template: " + adapter_id
            )
    unexpected = sorted(descriptor_names - RELEASE_ADAPTER_CATALOG_ENV_KEYS)
    if unexpected:
        errors.append("adapter schema keys missing from release catalogue: " + ", ".join(unexpected))
    # A full source checkout must keep the static archive catalogue and its
    # reviewed descriptors in exact parity. Selected-adapter archives omit
    # unrelated descriptor directories by design, so their strict validator
    # can only enforce the fixed blank catalogue.
    if descriptor_ids == RELEASE_ADAPTER_CATALOG_IDS and descriptor_names != RELEASE_ADAPTER_CATALOG_ENV_KEYS:
        errors.append("release adapter catalogue does not match reviewed descriptor schemas")
    return RELEASE_ADAPTER_CATALOG_ENV_KEYS


def _extension_catalog_environment_keys(root: Path, errors: list[str]) -> frozenset[str]:
    extension_ids = {path.parent.name for path in (root / "extensions").glob("*/extension.json")}
    try:
        names = extension_environment_catalog_names(root)
    except (EnvironmentPolicyError, ValueError):
        errors.append("extension environment schema unavailable for release template")
        return RELEASE_EXTENSION_CATALOG_ENV_KEYS
    unexpected = sorted(names - RELEASE_EXTENSION_CATALOG_ENV_KEYS)
    if unexpected:
        errors.append("extension schema keys missing from release catalogue: " + ", ".join(unexpected))
    if extension_ids == RELEASE_EXTENSION_CATALOG_IDS and names != RELEASE_EXTENSION_CATALOG_ENV_KEYS:
        errors.append("release extension catalogue does not match reviewed descriptor schemas")
    return RELEASE_EXTENSION_CATALOG_ENV_KEYS


def _validate_release_environment_contract(root: Path, errors: list[str]) -> None:
    """Validate the shipped template, not the operator's private live inputs.

    The builder always materializes ``.env`` from ``.env.example``. Reading a
    private operator file here would make a clean source checkout impossible to
    validate and would not strengthen the archive contract. The template and
    every adapter ``env.example`` remain scanned below.
    """

    template_path = root / ".env.example"
    template_values: dict[str, str] = {}
    try:
        template_values = _read_dotenv_compat(template_path)
    except EnvironmentPolicyError as exc:
        errors.append(f".env.example is not a valid dotenv template: {exc}")
    else:
        try:
            result = resolve_manifest(root, env=template_values, parent={})
            errors.extend(f".env.example resolved configuration invalid: {error}" for error in result.errors)
        except (EnvironmentPolicyError, ValueError) as exc:
            errors.append(f".env.example resolved configuration invalid: {exc}")
    template_assignments = _environment_assignments(_text(template_path))
    template_controls: dict[str, str] = {}
    core_event_keys = {field.name for field in CORE_EVENT_ENVIRONMENT_SCHEMA}
    adapter_catalog_keys = _adapter_catalog_environment_keys(root, errors)
    extension_catalog_keys = _extension_catalog_environment_keys(root, errors)
    allowed_template_keys = RELEASE_CORE_ENV_KEYS | core_event_keys | adapter_catalog_keys | extension_catalog_keys
    for key, value in template_assignments:
        template_controls[key] = _assignment_value(value)
        if key not in allowed_template_keys:
            errors.append(f"undeclared release configuration key in .env.example: {key}")
        elif key in RELEASE_NAMES_ONLY_ENV_CONTROLS and not _is_names_only_environment_array(value):
            errors.append(f"{key} must be a names-only JSON string array in .env.example")
        elif key in adapter_catalog_keys and _assignment_value(value):
            errors.append(f"adapter catalogue value must be blank in .env.example: {key}")
        elif key in extension_catalog_keys and _assignment_value(value):
            errors.append(f"extension catalogue value must be blank in .env.example: {key}")
    for key in sorted(adapter_catalog_keys - set(template_controls)):
        errors.append(f"adapter catalogue key missing from .env.example: {key}")
    for key in sorted(extension_catalog_keys - set(template_controls)):
        errors.append(f"extension catalogue key missing from .env.example: {key}")
    for descriptor in sorted((root / "adapters").glob("*/adapter.json")):
        adapter_id = descriptor.parent.name
        example_path = descriptor.parent / "env.example"
        if not example_path.is_file():
            continue
        try:
            example_values = _read_dotenv_compat(example_path)
            resolve_event_environment(root, profile=adapter_id, env=example_values, parent={})
        except (EnvironmentPolicyError, ValueError) as exc:
            errors.append(f"adapter environment example invalid: {adapter_id}: {exc}")
    for descriptor in sorted((root / "extensions").glob("*/extension.json")):
        extension_id = descriptor.parent.name
        example_path = descriptor.parent / "env.example"
        if not example_path.is_file():
            continue
        try:
            example_values = _read_dotenv_compat(example_path)
            example_values.setdefault("PLATFORM_ADAPTER", "manual")
            example_values.setdefault("EVENT_EXTENSIONS", extension_id)
            resolve_event_environment(root, profile="manual", env=example_values, parent={})
        except (EnvironmentPolicyError, ValueError) as exc:
            errors.append(f"extension environment example invalid: {extension_id}: {exc}")
    if template_controls.get("ROOKERY_ALLOW_INSTALL_NETWORK") != "0":
        errors.append("ROOKERY_ALLOW_INSTALL_NETWORK must default to 0 in .env.example")
    if template_controls.get("SEARXNG_IMAGE") != APPROVED_MANAGED_SEARXNG_IMAGE:
        errors.append("SEARXNG_IMAGE must be the approved exact OCI reference in .env.example")
    controls = {
        key: value
        for key, value in template_controls.items()
        if key
        in {
            "CODEX_AUTH_MODE",
            "CODEX_PROVIDER_ENV_KEYS",
            "CODEX_NETWORK_ENV_KEYS",
        }
    }
    mode = controls.get("CODEX_AUTH_MODE", "local-login")
    if mode not in {"local-login", "environment"}:
        errors.append("CODEX_AUTH_MODE must be local-login or environment")
    named_arrays: dict[str, list[str]] = {}
    for key in ("CODEX_PROVIDER_ENV_KEYS", "CODEX_NETWORK_ENV_KEYS"):
        raw = controls.get(key, "")
        if not raw:
            named_arrays[key] = []
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            errors.append(f"{key} must be a JSON string array")
            continue
        if (
            not isinstance(value, list)
            or any(not isinstance(item, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", item) for item in value)
            or len(value) != len(set(value))
        ):
            errors.append(f"{key} must be a unique JSON string array")
            continue
        named_arrays[key] = value
    if mode == "local-login" and any(named_arrays.values()):
        errors.append("local-login forbids CODEX_PROVIDER_ENV_KEYS and CODEX_NETWORK_ENV_KEYS")


def _validate_descriptor(root: Path, kind: str, descriptor: Path, errors: list[str]) -> None:
    rel = descriptor.relative_to(root).as_posix()
    data = load_json(descriptor, {})
    expected_id = descriptor.parent.name
    if not isinstance(data, dict):
        errors.append(f"invalid {kind[:-1]} descriptor: {rel}")
        return
    if data.get("id") != expected_id:
        errors.append(f"{kind[:-1]} descriptor id does not match directory: {rel}")
    allowed_fields = {
        "profile",
        "module",
        "agents",
        "tools",
        "docs",
        "env_example",
        "codex_config",
        "overlay",
    }
    for key in allowed_fields:
        value = data.get(key)
        if not value:
            continue
        target = descriptor.parent / str(value)
        try:
            target.resolve().relative_to(descriptor.parent.resolve())
        except ValueError:
            errors.append(f"{kind[:-1]} descriptor path escapes bundle: {rel}:{key}")
            continue
        if not target.exists():
            errors.append(f"{kind[:-1]} descriptor path missing: {rel}:{key}={value}")


def _validate_agents(root: Path, errors: list[str]) -> None:
    agent_paths = list((root / "agents" / "catalog").glob("*.toml"))
    agent_paths += list((root / "adapters").glob("*/agents/*.toml"))
    agent_paths += list((root / "extensions").glob("*/agents/*.toml"))
    for path in sorted(agent_paths):
        rel = path.relative_to(root).as_posix()
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            errors.append(f"agent TOML invalid: {rel}: {exc}")
            continue
        for key in ("name", "description", "developer_instructions"):
            if key not in data:
                errors.append(f"agent missing {key}: {rel}")
        text = path.read_text(encoding="utf-8", errors="ignore")
        for banned in ("model =", "service_type =", "gpt-5.4", "gpt-5.4-mini"):
            if banned in text:
                errors.append(f"fixed model/service pin in {rel}: {banned.strip()}")


def _validate_registries(root: Path, adapter_ids: list[str], extension_ids: list[str], errors: list[str]) -> None:
    base_agents = load_registry(root, "agents")
    base_tools = load_registry(root, "tools")
    errors.extend(validate_admission(base_agents, kind="agent"))
    errors.extend(validate_admission(base_tools, kind="tool"))
    for kind, key, entries in (
        ("agents", "source", base_agents),
        ("tools", "path", base_tools),
    ):
        for entry in entries:
            rel = str(entry.get(key, ""))
            if not rel or not (root / rel).exists():
                errors.append(f"{kind} registry path missing: {entry.get('id')}: {rel}")
    for ident in adapter_ids:
        descriptor = load_json(root / "adapters" / ident / "adapter.json", {}) or {}
        for kind in ("agents", "tools"):
            rel = descriptor.get(kind)
            if not rel:
                continue
            entries = load_json(root / "adapters" / ident / str(rel), [])
            if not isinstance(entries, list):
                errors.append(f"adapter {ident} {kind} registry invalid")
                continue
            errors.extend(validate_admission(entries, kind=f"adapter {ident} {kind[:-1]}"))
            key = "source" if kind == "agents" else "path"
            for entry in entries:
                source = str(entry.get(key, ""))
                if not source or not (root / source).exists():
                    errors.append(f"adapter {ident} registry path missing: {entry.get('id')}: {source}")
    for ident in extension_ids:
        descriptor = load_json(root / "extensions" / ident / "extension.json", {}) or {}
        for kind in ("agents", "tools"):
            rel = descriptor.get(kind)
            if not rel:
                continue
            entries = load_json(root / "extensions" / ident / str(rel), [])
            if not isinstance(entries, list):
                errors.append(f"extension {ident} {kind} registry invalid")
                continue
            errors.extend(validate_admission(entries, kind=f"extension {ident} {kind[:-1]}"))
            key = "source" if kind == "agents" else "path"
            for entry in entries:
                source = str(entry.get(key, ""))
                if not source or not (root / source).exists():
                    errors.append(f"extension {ident} registry path missing: {entry.get('id')}: {source}")


def validate_tree(
    root: Path,
    *,
    adapter: str | None = None,
    strict_release: bool = True,
    source_checkout: bool = False,
) -> dict[str, Any]:
    """Validate a Rookery source or release tree without modifying it."""

    root = root.resolve()
    # The legacy migration input stays outside the normal release contract. Do
    # not hash its private payload while checking an env-only release tree.
    before = tree_hash(root, exclude={LEGACY_EVENT_FILE})
    errors: list[str] = []
    warnings: list[str] = []
    release = load_json(root / "release.json", {})
    if not isinstance(release, dict):
        errors.append("release.json missing or invalid")
        release = {}
    elif release.get("identity") != "rookery":
        errors.append("release identity must be rookery")

    version_path = root / "VERSION"
    version = version_path.read_text(errors="ignore").strip() if version_path.exists() else ""
    if not re.fullmatch(r"\d{4}\.\d{2}\.\d{2}(?:\.\d+)?", version):
        errors.append("VERSION must contain a CalVer value such as 2026.08.28")
    else:
        try:
            dt.date(*map(int, version.split(".")[:3]))
        except ValueError:
            errors.append("VERSION must contain a valid calendar date")
    if str(release.get("version") or "") != version:
        errors.append("release.json version must match VERSION")

    _validate_child_environment_launches(root, errors)
    _validate_startup_entrypoints(root, errors)
    _validate_core_bin_python_shebangs(root, errors)
    _validate_adapter_extension_python_shebangs(root, errors)
    _validate_release_environment_contract(root, errors)

    for rel in release.get("required_paths", []):
        if (
            not (root / str(rel)).exists()
            and not (
                source_checkout
                and str(rel) in RELEASE_CONFIGURATION_TEMPLATES
            )
        ):
            errors.append(f"required release path missing: {rel}")

    if strict_release:
        allowed_top_level = {
            str(value) for key in ("base_roots", "optional_bundle_roots") for value in release.get(key, [])
        }
        allowed_top_level.update(
            Path(str(value)).parts[0] for value in release.get("required_paths", []) if Path(str(value)).parts
        )
        # A root-level legacy event file is a migration input only. It has no
        # launch or archive role, but allowing its presence lets an operator
        # migrate in place without making strict validation parse private data.
        allowed_top_level.add("event.json")
        allowed_top_level.update({".gitignore", "release.json"})
        for path in root.iterdir():
            if path.name not in allowed_top_level:
                errors.append(f"undeclared top-level release path: {path.name}")

    adapter_ids = _iter_descriptor_ids(root, "adapters")
    extension_ids = _iter_descriptor_ids(root, "extensions")
    for descriptor in sorted((root / "adapters").glob("*/adapter.json")):
        _validate_descriptor(root, "adapters", descriptor, errors)
    for descriptor in sorted((root / "extensions").glob("*/extension.json")):
        _validate_descriptor(root, "extensions", descriptor, errors)

    base_profiles = {p.stem for p in (root / "profiles").glob("*.json")}
    unexpected_profiles = sorted(base_profiles - {"generic", "manual"})
    if unexpected_profiles:
        errors.append("platform-specific profiles present in base profiles/: " + ", ".join(unexpected_profiles))

    if strict_release:
        for rel in release.get("forbidden_runtime_paths", []):
            path = root / str(rel)
            if path.is_file() or path.is_symlink():
                errors.append(f"runtime artifact present: {rel}")
            elif path.is_dir() and any(p.is_file() for p in path.rglob("*")):
                errors.append(f"runtime directory contains files: {rel}")
        active_agents = root / ".codex" / "agents"
        if active_agents.exists() and any(p.suffix == ".toml" for p in active_agents.iterdir() if p.is_file()):
            errors.append("generated active agents present under .codex/agents")

    forbidden_names = {str(x).lower() for x in release.get("forbidden_release_files", [])}
    for path in root.rglob("*"):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            try:
                path.resolve(strict=False).relative_to(root)
            except ValueError:
                errors.append(f"symlink escapes Rookery root: {rel}")
            continue
        if path.is_dir():
            if path.name == "__pycache__":
                errors.append(f"cache directory present: {rel}")
            continue
        if not path.is_file():
            continue
        # This exact root file is read only by `config migrate-event`. Normal
        # validation must not parse, scan, hash, or report its private payload.
        if rel == LEGACY_EVENT_FILE:
            continue
        lower_name = path.name.lower()
        crlf_sensitive = lower_name in {".env", ".env.example", "env.example"}
        if path.stat().st_size <= 2 * 1024 * 1024:
            raw = path.read_bytes()
            crlf_sensitive = crlf_sensitive or raw.startswith(b"#!")
            if crlf_sensitive and b"\r\n" in raw:
                errors.append(f"CRLF line endings in shell-consumed release file: {rel}")
        if lower_name in forbidden_names:
            errors.append(f"forbidden release file present: {rel}")
        if path.suffix.lower() in {".ovpn", ".pem", ".p12", ".pfx", ".pyc", ".pyo"}:
            errors.append(f"credential/cache material present: {rel}")
        if lower_name.endswith(".pid") or lower_name == "pid":
            errors.append(f"pid artifact present: {rel}")
        if any(fragment in path.name for fragment in RUNTIME_NAME_FRAGMENTS):
            errors.append(f"runtime residue present: {rel}")
        if path.stat().st_size > 8 * 1024 * 1024 and not rel.startswith(("souls/", "fixtures/")):
            warnings.append(f"large release file: {rel}")
        if _is_environment_or_default_file(path) and path.stat().st_size < 2 * 1024 * 1024:
            # A live dotenv is private operator input. The semantic check
            # below parses it in memory, while this public residue scan never
            # inspects or reports its values.
            if rel == ".env":
                continue
            text = _text(path)
            if _contains_credential_material(text):
                errors.append(f"secret-shaped assignment in {rel}")
            for match in ABSOLUTE_LOCAL.finditer(text):
                value = match.group(0)
                if value.startswith("/path/to/") or "<" in value:
                    continue
                errors.append(f"absolute local path in {rel}: {value[:120]}")
                break

    # Platform and activity-mode names may exist only inside their own optional
    # bundles or deterministic tests that prove isolation.
    platform_terms = sorted(set(adapter_ids + extension_ids), key=len, reverse=True)
    for path in _iter_contract_files(root, release):
        rel = path.relative_to(root).as_posix()
        text = _text(path)
        lowered = text.lower()
        # The root template and operator documentation are intentionally the
        # public catalogue for all optional adapters. Runtime controllers,
        # generic prompts, and registries remain subject to the isolation
        # check below.
        if rel != ".env.example" and not rel.startswith("docs/"):
            for term in platform_terms:
                if re.search(rf"(?<![a-z0-9_.-]){re.escape(term.lower())}(?![a-z0-9_.-])", lowered):
                    errors.append(f"optional bundle name leaked into generic contract {rel}: {term}")
        for pattern in OLD_PROJECT_NAMES:
            if pattern.search(text):
                errors.append(f"old project naming in generic contract {rel}: {pattern.pattern}")

    # Top-level executable and agent filenames must not be adapter/extension named.
    for base in (root / "bin", root / "agents" / "catalog", root / "configs"):
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            name = path.name.lower()
            for term in platform_terms:
                if term.lower() in name:
                    errors.append(f"optional bundle file present in base surface: {path.relative_to(root)}")

    _validate_agents(root, errors)
    _validate_registries(root, adapter_ids, extension_ids, errors)

    selected_adapter = adapter or "manual"
    try:
        if source_checkout:
            # A source check validates the public template without reading a
            # private operator file that happens to be present in the tree.
            result = resolve_manifest(
                root,
                profile=selected_adapter,
                env={"PLATFORM_ADAPTER": selected_adapter},
                parent={},
            )
        else:
            # An installed release must validate the same typed dotenv input
            # that launch will use. The values stay in memory and out of this
            # report; errors contain only field names or stable reason codes.
            result = resolve_manifest(root, profile=adapter, parent={})
            selected_adapter = str(result.manifest.get("adapter", {}).get("id") or selected_adapter)
            errors.extend(
                f"resolved configuration incomplete: {field}"
                for field in result.unresolved_required
            )
        errors.extend(f"resolved configuration invalid: {error}" for error in result.errors)
        if not source_checkout and not result.errors and not result.unresolved_required:
            from .environment import _codex_controls, _selected_adapter_contract, normalize_measurement_baseline_path

            try:
                normalize_measurement_baseline_path(
                    root,
                    _codex_controls(root, parent={}).get("ROOKERY_MEASUREMENT_BASELINE_PATH"),
                )
            except EnvironmentPolicyError as exc:
                errors.append(f"resolved configuration incomplete: ROOKERY_MEASUREMENT_BASELINE_PATH ({exc})")
            _selected_adapter_contract(root, result.manifest)
        if selected_adapter == "manual" and profile_has_platform_assumption(result.manifest, adapter_ids):
            errors.append("generic manual configuration contains optional platform assumptions")
    except Exception as exc:
        errors.append(f"adapter/profile validation failed: {exc}")

    # Compile Python and syntax-check shell without producing bytecode or artifacts.
    python_paths = list((root / "lib").rglob("*.py"))
    python_paths += [
        p for p in (root / "bin").glob("*") if p.is_file() and _text(p).startswith("#!/usr/bin/env python")
    ]
    python_paths += list((root / "adapters").glob("*/**/*.py"))
    python_paths += list((root / "extensions").glob("*/**/*.py"))
    for path in sorted(set(python_paths)):
        try:
            compile(path.read_text(encoding="utf-8"), str(path), "exec")
        except Exception as exc:
            errors.append(f"python compile failed: {path.relative_to(root)}: {exc}")
    shell_paths = [p for p in (root / "bin").glob("*") if p.is_file() and _text(p).startswith("#!/usr/bin/env bash")]
    shell_paths += [
        p for p in (root / "adapters").glob("*/bin/*") if p.is_file() and _text(p).startswith("#!/usr/bin/env bash")
    ]
    shell_paths += [
        p for p in (root / "extensions").glob("*/bin/*") if p.is_file() and _text(p).startswith("#!/usr/bin/env bash")
    ]
    executable_paths = [root / "go", root / "run-codex"]
    executable_paths += [p for p in (root / "bin").glob("*") if p.is_file() and _text(p).startswith("#!")]
    executable_paths += [p for p in (root / "adapters").glob("*/bin/*") if p.is_file() and _text(p).startswith("#!")]
    executable_paths += [p for p in (root / "extensions").glob("*/bin/*") if p.is_file() and _text(p).startswith("#!")]
    for path in executable_paths:
        if path.is_file() and path.stat().st_mode & 0o111 == 0:
            errors.append(f"deployed command is not executable: {path.relative_to(root)}")
    if shutil_which_bash := __import__("shutil").which("bash"):
        # `bash -n` does not execute the file. Keep source checks independent
        # of an optional private .env and pass no operator credential to bash.
        validation_environment = minimal_child_environment(
            root / ".validator-empty", policy_name="release-validator"
        )
        for path in shell_paths:
            cp = subprocess.run(
                [shutil_which_bash, "-n", str(path)],
                text=True,
                capture_output=True,
                env=validation_environment.values,
            )
            if cp.returncode != 0:
                errors.append(f"shell syntax failed: {path.relative_to(root)}: {cp.stderr.strip()}")

    after = tree_hash(root, exclude={LEGACY_EVENT_FILE})
    if before != after:
        errors.append("validator modified the Rookery tree")
    return {
        "ok": not errors,
        "errors": sorted(set(errors)),
        "warnings": sorted(set(warnings)),
        "tree_hash_before": before,
        "tree_hash_after": after,
        "adapter": selected_adapter,
        "adapters": adapter_ids,
        "extensions": extension_ids,
    }
