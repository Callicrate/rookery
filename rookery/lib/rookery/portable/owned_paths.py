from __future__ import annotations

import hashlib
import unicodedata
from pathlib import Path

from .util import (
    PORTABLE_COMPONENT_MAX_LENGTH,
    contained_private_path,
    path_component_id,
)


OPAQUE_IDENTIFIER_MAX_BYTES = 4096
_SHA256_HEX_LENGTH = 64
_OPAQUE_PREFIX_MAX_LENGTH = (
    PORTABLE_COMPONENT_MAX_LENGTH - _SHA256_HEX_LENGTH - 1
)


def opaque_identifier_component(
    value: str,
    *,
    label: str = "identifier",
    prefix: str,
) -> str:
    """Return a bounded, portable component derived from exact external data.

    This deliberately hashes rather than normalizes external identifiers, so
    distinct source values remain distinct filesystem component values.
    """

    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be non-empty text")
    if any(unicodedata.category(character) == "Cc" for character in value):
        raise ValueError(f"{label} must not contain control characters")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{label} must be valid UTF-8 text") from exc
    if len(encoded) > OPAQUE_IDENTIFIER_MAX_BYTES:
        raise ValueError(
            f"{label} exceeds the {OPAQUE_IDENTIFIER_MAX_BYTES}-byte limit"
        )

    prefix = path_component_id(prefix, label=f"{label} prefix")
    if len(prefix) > _OPAQUE_PREFIX_MAX_LENGTH:
        raise ValueError(
            f"{label} prefix exceeds {_OPAQUE_PREFIX_MAX_LENGTH} characters"
        )
    return f"{prefix}-{hashlib.sha256(encoded).hexdigest()}"


def objective_storage_component(raw_id: str) -> str:
    """Map an exact objective ID to one portable storage component.

    Every bounded raw ID receives the same opaque form, preventing a safe raw
    ID from colliding with the storage component of an unsafe external ID.
    Canonical events and payloads retain the exact raw value separately.
    """

    return opaque_identifier_component(
        raw_id,
        label="objective ID",
        prefix="challenge",
    )


def owned_identifier_path(
    root: Path,
    parent: Path,
    identifier: str,
    *,
    label: str = "identifier",
) -> Path:
    """Compatibility entrypoint for one contained, portable identifier path."""

    return contained_private_path(
        root,
        parent,
        path_component_id(identifier, label=label),
    )
