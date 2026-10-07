"""Declared configuration and child-environment policies for Guac helpers.

The extension deliberately keeps its runtime configuration separate from the
environment of a configured transport.  A helper resolves only its own
names-only controls, then constructs a fresh child environment for the one
transport it is about to invoke.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from rookery.portable.environment import (
    ChildEnvironment,
    EnvClass,
    EnvKey,
    EnvironmentPolicyError,
    ResolvedEnvironment,
    build_child_environment,
    classify_environment_name,
    minimal_child_environment,
    parse_name_array,
    purpose_policy,
    read_declared_environment,
)

_CONFIGURATION_NAMES = (
    "GUAC_STREAM_DIR",
    "GUAC_REMOTE_FILE_EXPORT_ARGV",
    "GUAC_CLIPBOARD_EXPORT_ARGV",
    "GUAC_BASE64_EXPORT_ARGV",
    "GUAC_HTTP_EXPORT_ARGV",
    "GUAC_SCREENSHOT_TRANSCRIBE_ARGV",
    "GUAC_TERMINAL_CAPTURE_ARGV",
    "GUAC_SSH_EXEC_ARGV",
    "GUAC_EXEC_TIMEOUT",
    # Legacy shell templates remain declarations so their presence can fail
    # closed without loading unrelated operator configuration.
    "GUAC_REMOTE_FILE_EXPORT_COMMAND",
    "GUAC_CLIPBOARD_EXPORT_COMMAND",
    "GUAC_BASE64_EXPORT_COMMAND",
    "GUAC_HTTP_EXPORT_COMMAND",
    "GUAC_SCREENSHOT_TRANSCRIBE_COMMAND",
    "GUAC_TERMINAL_CAPTURE_COMMAND",
    "GUAC_SSH_EXEC_COMMAND",
    "GUAC_EXEC_COMMAND",
    "GUAC_REMOTE_FILE_EXPORT_ENV_KEYS",
    "GUAC_CLIPBOARD_EXPORT_ENV_KEYS",
    "GUAC_BASE64_EXPORT_ENV_KEYS",
    "GUAC_HTTP_EXPORT_ENV_KEYS",
    "GUAC_SCREENSHOT_TRANSCRIBE_ENV_KEYS",
    "GUAC_TERMINAL_CAPTURE_ENV_KEYS",
    "GUAC_SSH_EXEC_ENV_KEYS",
)

GUAC_CONFIGURATION_KEYS = tuple(
    EnvKey(
        name,
        EnvClass.CAPABILITY_PATH if name == "GUAC_STREAM_DIR" else EnvClass.ROOKERY_CONFIG,
    )
    for name in _CONFIGURATION_NAMES
)

_TRANSPORT_SELECTORS = frozenset(
    {
        "GUAC_REMOTE_FILE_EXPORT_ENV_KEYS",
        "GUAC_CLIPBOARD_EXPORT_ENV_KEYS",
        "GUAC_BASE64_EXPORT_ENV_KEYS",
        "GUAC_HTTP_EXPORT_ENV_KEYS",
        "GUAC_SCREENSHOT_TRANSCRIBE_ENV_KEYS",
        "GUAC_TERMINAL_CAPTURE_ENV_KEYS",
        "GUAC_SSH_EXEC_ENV_KEYS",
    }
)
_SSH_TRANSPORT_SELECTOR = "GUAC_SSH_EXEC_ENV_KEYS"
_SAFE_TRANSPORT_CLASSES = frozenset(
    {
        EnvClass.OS_RUNTIME,
        EnvClass.TERMINAL_SETTING,
        EnvClass.ROOKERY_CONFIG,
        EnvClass.CAPABILITY_PATH,
        EnvClass.PROXY_CREDENTIAL,
        EnvClass.CA_TRUST_PATH,
        EnvClass.UNKNOWN_EXPLICIT,
    }
)


def read_guac_configuration(
    root: Path, *, parent: Mapping[str, str] | None = None
) -> ResolvedEnvironment:
    """Resolve exactly the Guac extension's own controls.

    ``read_declared_environment`` validates the complete dotenv grammar while
    returning only these declarations, with the documented dotenv-before-parent
    precedence.  Call this before creating output or launching a transport.
    """

    return read_declared_environment(root, GUAC_CONFIGURATION_KEYS, parent=parent)


def transport_child_environment(
    root: Path,
    configuration: ResolvedEnvironment,
    *,
    policy_name: str,
    keys_control: str,
    parent: Mapping[str, str] | None = None,
) -> ChildEnvironment:
    """Build one selector's least-privilege custom transport environment."""

    if keys_control not in _TRANSPORT_SELECTORS:
        raise EnvironmentPolicyError(
            "unknown Guacamole transport environment selector"
        )

    names = parse_name_array(
        configuration.get(keys_control), label=keys_control
    )
    declarations: list[EnvKey] = []
    allowed_classes = set(_SAFE_TRANSPORT_CLASSES)
    if keys_control == _SSH_TRANSPORT_SELECTOR:
        allowed_classes.add(EnvClass.AGENT_CAPABILITY)
    for name in names:
        classification = classify_environment_name(name)
        if classification is EnvClass.AGENT_CAPABILITY and not (
            keys_control == _SSH_TRANSPORT_SELECTOR and name == "SSH_AUTH_SOCK"
        ):
            raise EnvironmentPolicyError(
                f"{keys_control} forbids agent capability: {name}"
            )
        if classification not in allowed_classes:
            raise EnvironmentPolicyError(
                f"{keys_control} forbids class {classification.value}: {name}"
            )
        declarations.append(EnvKey(name, classification, required=True))
    return build_child_environment(
        root,
        policy=purpose_policy(
            policy_name,
            declarations,
            allowed_classes=allowed_classes,
        ),
        parent=parent,
    )


def interactive_desktop_environment(
    root: Path, *, parent: Mapping[str, str] | None = None
) -> ChildEnvironment:
    """Build the one explicit desktop policy used by the xdotool fallback."""

    desktop = ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS")
    return build_child_environment(
        root,
        policy=purpose_policy(
            "guac-xdotool-interactive-desktop",
            tuple(EnvKey(name, EnvClass.AGENT_CAPABILITY) for name in desktop),
        ),
        parent=parent,
    )


def guac_minimal_environment(
    root: Path, *, policy_name: str
) -> ChildEnvironment:
    """Name the policy for a nested helper that needs no transport authority."""

    return minimal_child_environment(root, policy_name=policy_name)
