"""Explicit, purpose-scoped urllib/WebSocket transport authority.

The parent Rookery process may legitimately start from an operator shell.  It
must not consequently inherit that shell's proxy or TLS overrides.  This module
accepts only an already-resolved :class:`ChildEnvironment` and derives every
proxy, bypass, and trust choice from its declared entries.
"""

from __future__ import annotations

import ssl
import sys
import urllib.parse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .environment import (
    ChildEnvironment,
    EnvClass,
    EnvironmentPolicyError,
    read_ca_trust_material,
)
_NETWORK_CLASSES = frozenset(
    {EnvClass.PROXY_CREDENTIAL, EnvClass.CA_TRUST_PATH}
)


def _validated_proxy_url(value: str) -> urllib.parse.SplitResult:
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError):
        # ``urlsplit``/``port`` errors may quote untrusted userinfo.  Do not
        # retain that cause where a caller could render the exception chain.
        raise EnvironmentPolicyError("configured proxy URL is invalid") from None
    if (
        parsed.scheme.casefold() not in {"http", "https"}
        or not parsed.hostname
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise EnvironmentPolicyError("configured proxy URL is invalid")
    return parsed


def _system_trust_context() -> ssl.SSLContext:
    """Use compiled OS trust paths; never fall back to ambient CA variables."""

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    paths = ssl.get_default_verify_paths()
    cafile = paths.openssl_cafile
    capath = paths.openssl_capath
    try:
        if cafile and Path(cafile).is_file():
            context.load_verify_locations(cafile=cafile)
        elif capath and Path(capath).is_dir():
            context.load_verify_locations(capath=capath)
        # Linux/WSL must fail rather than calling ``load_default_certs()``,
        # which could consult SSL_CERT_FILE from the already-running process.
        elif sys.platform.startswith("linux"):
            raise EnvironmentPolicyError("system TLS trust store is unavailable")
        else:  # pragma: no cover - native Windows is a parser-only surface.
            context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    except (OSError, ssl.SSLError) as exc:
        raise EnvironmentPolicyError("system TLS trust store is unavailable") from exc
    return context


def system_trust_context() -> ssl.SSLContext:
    """Return the reviewed system trust context for direct pinned transports."""

    return _system_trust_context()


def _trust_context(ca_materials: Sequence[bytes]) -> ssl.SSLContext:
    """Extend explicit system trust from already-bound CA bundle bytes."""

    context = _system_trust_context()
    try:
        for material in dict.fromkeys(ca_materials):
            # Python's SSL API accepts PEM only as text and DER only as bytes.
            # Never pass ``cafile`` here: reopening the operator-controlled path
            # after admission would reintroduce a validation-to-use race.
            if b"-----BEGIN CERTIFICATE-----" in material:
                context.load_verify_locations(cadata=material.decode("ascii"))
            else:
                context.load_verify_locations(cadata=material)
    except (OSError, ssl.SSLError, UnicodeDecodeError, ValueError) as exc:
        raise EnvironmentPolicyError("declared TLS trust is invalid") from exc
    return context


def _network_values(environment: ChildEnvironment) -> tuple[dict[str, str], str, list[bytes]]:
    by_name: dict[str, str] = {}
    ca_materials: list[bytes] = []
    for passed in environment.passed:
        if passed.classification not in _NETWORK_CLASSES:
            continue
        value = environment.values.get(passed.name)
        if value is None:
            raise EnvironmentPolicyError("network environment is internally inconsistent")
        if passed.classification is EnvClass.CA_TRUST_PATH:
            material = environment.trust_material.get(passed.name)
            if material is None:
                # Compatibility for directly-created ChildEnvironment fixtures;
                # this helper still opens and consumes the path exactly once.
                material = read_ca_trust_material(passed.name, value)
            ca_materials.append(material)
            continue
        normalized = passed.name.upper()
        existing = by_name.get(normalized)
        if existing is not None and existing != value:
            raise EnvironmentPolicyError(f"conflicting proxy aliases: {normalized}")
        by_name[normalized] = value
    proxies: dict[str, str] = {}
    all_proxy = by_name.get("ALL_PROXY", "")
    for scheme, name in (("http", "HTTP_PROXY"), ("https", "HTTPS_PROXY")):
        value = by_name.get(name, "") or all_proxy
        if value:
            _validated_proxy_url(value)
            proxies[scheme] = value
    return proxies, by_name.get("NO_PROXY", ""), ca_materials


@dataclass(frozen=True)
class NoProxyRule:
    """One validated direct-bypass entry; no ambient proxy syntax is accepted."""

    host: str
    port: int | None
    suffix: bool = False

    def matches(self, host: str, port: int) -> bool:
        if self.host == "*":
            return True
        if self.port is not None and self.port != port:
            return False
        return host == self.host or (self.suffix and host.endswith("." + self.host))


def _canonical_no_proxy_host(value: str) -> str:
    from .scope import canonical_hostname

    if not value.isascii():
        raise EnvironmentPolicyError("configured NO_PROXY is invalid")
    try:
        return canonical_hostname(value)
    except ValueError as exc:
        raise EnvironmentPolicyError("configured NO_PROXY is invalid") from exc


def _no_proxy_rules(value: str) -> tuple[NoProxyRule, ...]:
    """Parse one documented, unambiguous NO_PROXY grammar at policy creation."""

    if not value:
        return ()
    rules: list[NoProxyRule] = []
    for raw in value.split(","):
        item = raw.strip()
        if not item:
            raise EnvironmentPolicyError("configured NO_PROXY is invalid")
        if item == "*":
            rules.append(NoProxyRule("*", None))
            continue
        suffix = item.startswith(".")
        if suffix:
            item = item[1:]
        host = item
        port: int | None = None
        if item.startswith("["):
            closing = item.find("]")
            if closing <= 1:
                raise EnvironmentPolicyError("configured NO_PROXY is invalid")
            host = item[1:closing]
            remainder = item[closing + 1 :]
            if remainder:
                if not remainder.startswith(":") or not remainder[1:].isdigit():
                    raise EnvironmentPolicyError("configured NO_PROXY is invalid")
                port = int(remainder[1:])
        elif item.count(":") == 1:
            possible_host, possible_port = item.rsplit(":", 1)
            if possible_port.isdigit():
                host, port = possible_host, int(possible_port)
        if port is not None and not 1 <= port <= 65535:
            raise EnvironmentPolicyError("configured NO_PROXY is invalid")
        if not host or any(token in host for token in "/@?#"):
            raise EnvironmentPolicyError("configured NO_PROXY is invalid")
        rules.append(NoProxyRule(_canonical_no_proxy_host(host), port, suffix))
    return tuple(rules)


@dataclass(frozen=True)
class ExplicitNetworkPolicy:
    """Resolved network authority with value-free metadata and diagnostics."""

    environment: ChildEnvironment = field(repr=False)
    proxies: Mapping[str, str] = field(repr=False)
    no_proxy: tuple[NoProxyRule, ...] = field(repr=False)
    trust_context: ssl.SSLContext = field(repr=False)

    @classmethod
    def from_child_environment(
        cls,
        environment: ChildEnvironment,
        *,
        scope: Mapping[str, Any] | None = None,
    ) -> "ExplicitNetworkPolicy":
        """Resolve explicit transport with an optional event-scope authority check."""

        del scope  # proxy scope is insufficient without numeric target pinning.
        proxies, no_proxy, ca_materials = _network_values(environment)
        return cls(
            environment=environment,
            proxies=dict(proxies),
            no_proxy=_no_proxy_rules(no_proxy),
            trust_context=_trust_context(ca_materials),
        )

    def metadata(self) -> dict[str, Any]:
        return self.environment.metadata()["environment"]

    def route_for(self, host: str, port: int, scheme: str) -> str:
        """Select direct only, or fail before resolver/socket/evidence effects."""

        proxy = self.proxies.get("https" if scheme.casefold() in {"https", "wss"} else "http")
        if proxy and not any(rule.matches(host, port) for rule in self.no_proxy):
            raise EnvironmentPolicyError("scoped_proxy_target_pinning_unavailable")
        return "direct"

    def scoped_transport(
        self,
        scope: Mapping[str, Any],
        *,
        platform: bool = False,
        overrides: list[dict[str, Any]] | None = None,
    ) -> Any:
        """Return the only supported HTTP(S) path for this declared policy."""

        from .scoped_transport import ScopedHTTPTransport

        return ScopedHTTPTransport(
            scope,
            self.trust_context,
            route_policy=self,
            platform=platform,
            overrides=overrides,
        )
