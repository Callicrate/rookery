from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path


_ASSIGNMENT = re.compile(r"^([A-Z][A-Z0-9_]*)=")


def replace_env_assignments(
    root: Path,
    values: Mapping[str, str],
    *,
    remove: tuple[str, ...] = ("EVENT_MANIFEST",),
) -> Path:
    """Replace dotenv assignments exactly once while preserving unrelated lines."""

    if any(_ASSIGNMENT.fullmatch(f"{name}=") is None for name in values):
        raise ValueError("dotenv fixture names must be uppercase assignment names")
    if any("\n" in value or "\r" in value for value in values.values()):
        raise ValueError("dotenv fixture values must be single-line text")
    environment = Path(root) / ".env"
    if environment.is_file():
        lines = environment.read_text(encoding="utf-8").splitlines()
    else:
        example = Path(root) / ".env.example"
        lines = example.read_text(encoding="utf-8").splitlines() if example.is_file() else []
    pending = dict(values)
    removed = set(remove)
    written: set[str] = set()
    output: list[str] = []
    for line in lines:
        match = _ASSIGNMENT.match(line)
        name = match.group(1) if match else ""
        if name in removed:
            continue
        if name in pending:
            if name not in written:
                output.append(f"{name}={pending[name]}")
                written.add(name)
            continue
        output.append(line)
    for name, value in pending.items():
        if name not in written:
            output.append(f"{name}={value}")
    environment.write_text("\n".join(output) + "\n", encoding="utf-8")
    return environment


def configure_event_environment(
    root: Path,
    adapter_id: str,
    *,
    ready: bool = True,
    name_suffix: str = "Event",
    extra: Mapping[str, str] | None = None,
) -> Path:
    """Install one complete env-only synthetic event without duplicate keys."""

    values = {
        "PLATFORM_ADAPTER": adapter_id,
        "EVENT_ID": f"{adapter_id}-event",
        "EVENT_NAME": f"{adapter_id.title()} {name_suffix}",
        "EVENT_URL": "https://fixture.invalid/event",
        "EVENT_SCOPE_ACK": "1" if ready else "0",
        "ALLOWED_HOSTS": "fixture.invalid,localhost,127.0.0.1",
        "ALLOWED_CIDRS": "192.0.2.0/24",
        "ALLOWED_PORTS": "80,443,31337",
        "ALLOWED_PROTOCOLS": "http,https,tcp",
        "ALLOWED_FILE_ORIGINS": "fixture://*,adapters/fixture/*",
        "PLATFORM_HOSTS": "fixture.invalid",
        "SCOPE_MAX_BYTES": "1048576",
        "FLAG_REGEX": r"FIXTURE\{[^}]+\}",
        "ANSWER_EXAMPLES_JSON": '["FIXTURE{ok}"]',
        "ROOKERY_PREPARE_MODE": "check",
        "SEARXNG_MODE": "disabled",
        "BROWSER_MODE": "disabled",
    }
    values.update(extra or {})
    return replace_env_assignments(root, values)
