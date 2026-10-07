"""Immersive selector binding backed by the shared explicit transport policy."""

from __future__ import annotations

from pathlib import Path

from rookery.portable.environment import (
    EnvClass,
    build_child_environment,
    parse_name_array,
    purpose_policy,
)
from rookery.portable.network_policy import ExplicitNetworkPolicy


_NETWORK_CLASSES = frozenset({EnvClass.PROXY_CREDENTIAL, EnvClass.CA_TRUST_PATH})

# The adapter retains its public type name, while proxy parsing, NO_PROXY
# matching, TLS setup, and WebSocket safeguards have one portable source.
ImmersiveNetworkPolicy = ExplicitNetworkPolicy


def resolve_network_policy(
    root: Path, raw_names: str | None
) -> ImmersiveNetworkPolicy:
    """Resolve exact Immersive proxy/CA names before a request begins."""

    names = parse_name_array(raw_names, label="IMMERSIVE_NETWORK_ENV_KEYS")
    environment = build_child_environment(
        root,
        policy=purpose_policy(
            "immersive-network",
            allowed_classes=_NETWORK_CLASSES,
        ),
        pass_names=names,
    )
    return ExplicitNetworkPolicy.from_child_environment(environment)
