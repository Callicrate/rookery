"""Direct, DNS-pinned HTTP(S) transport for compiled Rookery scope.

The standard urllib connector accepts a hostname and resolves it while
connecting.  That loses the result which the scope gate reviewed.  This module
instead accepts a complete, authorized resolution plan and only dials its
recorded numeric socket addresses.  It deliberately has no proxy support.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
import urllib.parse
import urllib.request
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .scope import (
    canonical_hostname,
    check_resolved_addresses,
    check_url,
    default_port_for_scheme,
)

MAX_RESOLVED_ADDRESSES = 32


class ScopedTransportError(RuntimeError):
    """A stable, value-free error raised by the scoped network boundary."""


@dataclass(frozen=True)
class ResolvedAddress:
    """One numeric destination returned by the single authorized lookup."""

    family: int
    sockaddr: tuple[Any, ...]
    address: ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True)
class ScopedConnectionPlan:
    """One already-authorized name/port resolution for a single connection."""

    url: str
    scheme: str
    host: str
    port: int
    candidates: tuple[ResolvedAddress, ...]


def _stable_failure(reason: str) -> ScopedTransportError:
    return ScopedTransportError(reason)


def _literal_address(host: str, port: int) -> tuple[ResolvedAddress, ...] | None:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv4Address):
        return (ResolvedAddress(socket.AF_INET, (str(address), port), address),)
    return (ResolvedAddress(socket.AF_INET6, (str(address), port, 0, 0), address),)


def _validated_answer(
    answer: tuple[Any, ...], *, port: int
) -> ResolvedAddress | None:
    """Normalize exactly the address shapes this direct TCP transport supports."""

    if len(answer) != 5:
        raise _stable_failure("scoped_dns_answer_invalid")
    family, socktype, protocol, _canonname, sockaddr = answer
    if family not in {socket.AF_INET, socket.AF_INET6}:
        raise _stable_failure("scoped_dns_answer_invalid")
    if socktype != socket.SOCK_STREAM or protocol not in {0, socket.IPPROTO_TCP}:
        raise _stable_failure("scoped_dns_answer_invalid")
    if not isinstance(sockaddr, tuple):
        raise _stable_failure("scoped_dns_answer_invalid")
    if family == socket.AF_INET:
        if len(sockaddr) != 2 or sockaddr[1] != port:
            raise _stable_failure("scoped_dns_answer_invalid")
        try:
            address = ipaddress.IPv4Address(sockaddr[0])
        except ipaddress.AddressValueError as exc:
            raise _stable_failure("scoped_dns_answer_invalid") from exc
        return ResolvedAddress(family, (str(address), port), address)
    if len(sockaddr) != 4 or sockaddr[1] != port or sockaddr[3] != 0:
        raise _stable_failure("scoped_dns_answer_invalid")
    try:
        address = ipaddress.IPv6Address(sockaddr[0])
    except ipaddress.AddressValueError as exc:
        raise _stable_failure("scoped_dns_answer_invalid") from exc
    return ResolvedAddress(family, (str(address), port, 0, 0), address)


def resolve_scoped_addresses(
    scope: Mapping[str, Any],
    host: str,
    port: int,
    *,
    overrides: list[dict[str, Any]] | None = None,
) -> tuple[ResolvedAddress, ...]:
    """Resolve once, normalize all answers, then authorize the complete set."""

    canonical_host = canonical_hostname(host)
    literal = _literal_address(canonical_host, port)
    if literal is not None:
        decision = check_resolved_addresses(
            scope, canonical_host, [entry.address for entry in literal], overrides=overrides
        )
        if not decision.allowed:
            raise _stable_failure("scoped_dns_answer_outside_scope")
        return literal
    try:
        answers = socket.getaddrinfo(
            canonical_host,
            port,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
        )
    except socket.gaierror as exc:
        raise _stable_failure("scoped_dns_resolution_failed") from exc
    if not answers or len(answers) > MAX_RESOLVED_ADDRESSES:
        raise _stable_failure("scoped_dns_answer_invalid")
    normalized: list[ResolvedAddress] = []
    seen: set[tuple[int, tuple[Any, ...]]] = set()
    for answer in answers:
        entry = _validated_answer(answer, port=port)
        key = (entry.family, entry.sockaddr)
        if key not in seen:
            seen.add(key)
            normalized.append(entry)
    if not normalized or len(normalized) > MAX_RESOLVED_ADDRESSES:
        raise _stable_failure("scoped_dns_answer_invalid")
    decision = check_resolved_addresses(
        scope, canonical_host, [entry.address for entry in normalized], overrides=overrides
    )
    if not decision.allowed:
        raise _stable_failure("scoped_dns_answer_outside_scope")
    return tuple(normalized)


def scoped_connection_plan(
    scope: Mapping[str, Any],
    url: str,
    *,
    route_policy: Any | None = None,
    platform: bool = False,
    overrides: list[dict[str, Any]] | None = None,
) -> ScopedConnectionPlan:
    """Create one direct numeric plan without opening a socket.

    This is the public boundary for consumers that need a raw TCP, WS, WSS, or
    numeric child-process target.  Calling it again intentionally creates a new
    resolution pass; a caller must retain this object across its one effect.
    """

    decision = check_url(dict(scope), url, platform=platform, overrides=overrides)
    if not decision.allowed:
        raise _stable_failure("scoped_url_outside_scope")
    try:
        parsed = urllib.parse.urlsplit(url)
        scheme = parsed.scheme.casefold()
        host = canonical_hostname(parsed.hostname or "")
        port = (
            parsed.port
            if parsed.port is not None
            else default_port_for_scheme(scheme)
        )
    except (ValueError, UnicodeError) as exc:
        raise _stable_failure("scoped_url_invalid") from exc
    if scheme not in {"http", "https", "ws", "wss", "tcp"}:
        raise _stable_failure("scoped_stream_scheme_unsupported")
    if route_policy is not None:
        route_policy.route_for(host, port, scheme)
    return ScopedConnectionPlan(
        url=url,
        scheme=scheme,
        host=host,
        port=port,
        candidates=resolve_scoped_addresses(scope, host, port, overrides=overrides),
    )


def _verify_peer(sock: socket.socket, selected: ResolvedAddress) -> None:
    try:
        peer = sock.getpeername()
        peer_address = ipaddress.ip_address(peer[0])
        peer_port = int(peer[1])
    except (OSError, ValueError, IndexError) as exc:
        raise _stable_failure("scoped_peer_verification_failed") from exc
    if peer_address != selected.address or peer_port != selected.sockaddr[1]:
        raise _stable_failure("scoped_peer_verification_failed")


def _connect_recorded(
    candidates: Iterable[ResolvedAddress], *, deadline: float
) -> socket.socket:
    last_error: OSError | None = None
    for candidate in candidates:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        stream = socket.socket(candidate.family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        try:
            stream.settimeout(remaining)
            stream.connect(candidate.sockaddr)
            _verify_peer(stream, candidate)
            return stream
        except ScopedTransportError:
            stream.close()
            raise
        except OSError as exc:
            last_error = exc
            stream.close()
    raise _stable_failure("scoped_tcp_connection_failed") from last_error


def _verified_tls_context(context: ssl.SSLContext) -> bool:
    return context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED


def connect_scoped_stream(
    plan: ScopedConnectionPlan,
    *,
    timeout: float,
    tls_context: ssl.SSLContext | None = None,
) -> socket.socket:
    """Connect one plan's recorded peer, TLS-wrapping HTTPS/WSS when needed.

    The caller owns the returned connected stream and must close it.  Address
    fallback happens only in ``_connect_recorded`` before a TLS handshake; a
    failed hostname/certificate validation closes the raw socket and does not
    attempt another candidate.
    """

    if timeout <= 0:
        raise ValueError("scoped stream timeout must be positive")
    if plan.scheme in {"https", "wss"} and tls_context is None:
        from .network_policy import system_trust_context

        tls_context = system_trust_context()
    if plan.scheme in {"https", "wss"} and (
        tls_context is None or not _verified_tls_context(tls_context)
    ):
        raise _stable_failure("scoped_tls_context_invalid")
    raw_socket = _connect_recorded(plan.candidates, deadline=time.monotonic() + timeout)
    if plan.scheme not in {"https", "wss"}:
        return raw_socket
    try:
        return tls_context.wrap_socket(raw_socket, server_hostname=plan.host)
    except (OSError, ssl.SSLError, ValueError) as exc:
        raw_socket.close()
        raise _stable_failure("scoped_tls_verification_failed") from exc


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection whose only dial path is a captured numeric plan."""

    def __init__(self, host: str, port: int, candidates: tuple[ResolvedAddress, ...], timeout: float):
        super().__init__(host, port=port, timeout=timeout)
        self._candidates = candidates
        self._deadline = time.monotonic() + timeout

    def connect(self) -> None:
        self.sock = _connect_recorded(self._candidates, deadline=self._deadline)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS keeps hostname validation/SNI while its TCP peer stays numeric."""

    def __init__(
        self,
        host: str,
        port: int,
        candidates: tuple[ResolvedAddress, ...],
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._candidates = candidates
        self._deadline = time.monotonic() + timeout

    def connect(self) -> None:
        raw_socket = _connect_recorded(self._candidates, deadline=self._deadline)
        try:
            # The original canonical DNS hostname, not the numeric peer, is the
            # certificate identity and TLS SNI.  A verification error is not a
            # TCP retry signal, so no candidate fallback is possible here.
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
        except (OSError, ssl.SSLError, ValueError) as exc:
            raw_socket.close()
            raise _stable_failure("scoped_tls_verification_failed") from exc


class PinnedHTTPResponse:
    """Response wrapper which closes the dedicated connection with its body."""

    def __init__(self, response: http.client.HTTPResponse, connection: http.client.HTTPConnection, url: str) -> None:
        self._response = response
        self._connection = connection
        self._url = url
        self.status = response.status
        self.headers = response.headers

    def read(self, amount: int = -1) -> bytes:
        return self._response.read(amount)

    def getcode(self) -> int:
        return int(self.status)

    def geturl(self) -> str:
        return self._url

    def close(self) -> None:
        try:
            self._response.close()
        finally:
            self._connection.close()

    def __enter__(self) -> "PinnedHTTPResponse":
        return self

    def __exit__(self, *args: object) -> None:
        del args
        self.close()


def _request_headers(request: urllib.request.Request, host: str, port: int, scheme: str) -> dict[str, str]:
    headers = dict(request.unredirected_hdrs)
    headers.update(request.headers)
    if any(name.casefold() == "host" for name in headers):
        raise _stable_failure("scoped_custom_host_header_rejected")
    host_header = f"[{host}]" if ":" in host else host
    if port != default_port_for_scheme(scheme):
        host_header = f"{host_header}:{port}"
    headers["Host"] = host_header
    if request.data is not None and not any(
        name.casefold() == "content-length" for name in headers
    ):
        headers["Content-Length"] = str(len(request.data))
    return headers


@dataclass(frozen=True)
class ScopedHTTPTransport:
    """One direct HTTP(S) transport bound to a compiled scope and TLS policy."""

    scope: Mapping[str, Any]
    tls_context: ssl.SSLContext
    route_policy: Any | None = None
    platform: bool = False
    overrides: list[dict[str, Any]] | None = None

    def _route(self, host: str, port: int, scheme: str) -> None:
        if self.route_policy is not None:
            self.route_policy.route_for(host, port, scheme)

    def preflight_url(self, url: str) -> None:
        """Reject a selected proxy before any DNS, socket, or evidence effect."""

        decision = check_url(
            dict(self.scope), url, platform=self.platform, overrides=self.overrides
        )
        if not decision.allowed:
            raise _stable_failure("scoped_url_outside_scope")
        try:
            parsed = urllib.parse.urlsplit(url)
            host = canonical_hostname(parsed.hostname or "")
            port = (
                parsed.port
                if parsed.port is not None
                else default_port_for_scheme(parsed.scheme.casefold())
            )
        except ValueError as exc:
            raise _stable_failure("scoped_url_invalid") from exc
        self._route(host, port, parsed.scheme.casefold())

    def open(self, request: urllib.request.Request, *, timeout: float) -> PinnedHTTPResponse:
        if timeout <= 0:
            raise ValueError("HTTP timeout must be positive")
        parsed = urllib.parse.urlsplit(request.full_url)
        if parsed.scheme.casefold() == "https" and not _verified_tls_context(
            self.tls_context
        ):
            raise _stable_failure("scoped_tls_context_invalid")
        plan = scoped_connection_plan(
            self.scope,
            request.full_url,
            route_policy=self.route_policy,
            platform=self.platform,
            overrides=self.overrides,
        )
        if plan.scheme not in {"http", "https"}:
            raise _stable_failure("scoped_http_scheme_unsupported")
        if plan.scheme == "https":
            connection: http.client.HTTPConnection = _PinnedHTTPSConnection(
                plan.host, plan.port, plan.candidates, timeout, self.tls_context
            )
        else:
            connection = _PinnedHTTPConnection(
                plan.host, plan.port, plan.candidates, timeout
            )
        target = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        try:
            connection.request(
                request.get_method().upper(),
                target,
                body=request.data,
                headers=_request_headers(request, plan.host, plan.port, plan.scheme),
            )
            return PinnedHTTPResponse(connection.getresponse(), connection, request.full_url)
        except ScopedTransportError:
            connection.close()
            raise
        except (OSError, http.client.HTTPException, ValueError) as exc:
            connection.close()
            raise _stable_failure("scoped_http_request_failed") from exc
