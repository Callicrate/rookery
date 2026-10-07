from __future__ import annotations

import hmac
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rookery.portable import browser_cdp as _browser_cdp
from rookery.portable.adapters import (
    DEFAULT_ADAPTER_OUTPUT_BYTES,
    MAX_ADAPTER_OUTPUT_BYTES,
    Adapter,
    CapabilityHealth,
    bounded_response_bytes,
    normalized_snapshot,
)
from rookery.portable.browser_cdp import BrowserCdpError
from rookery.portable.browser_cdp_scoring import (
    BrowserCdpScoringError,
    BrowserScoringBinding,
    CTFdReadOnlyRequest,
    CTFdScoringAction,
    _bounded_json_document,
    bootstrap_owned_browser_target,
    execute_ctfd_browser_read,
    execute_ctfd_browser_scoring,
    parse_ctfd_attempt_verdict,
)
from rookery.portable.browser_gateway_policy import (
    BrowserGatewayPolicyError,
    canonical_gateway_origin,
    browser_gateway_origin,
    compile_browser_gateway_policy,
    policy_sha256,
    scope_sha256,
)
from rookery.portable.environment import (
    BrowserGatewayReadiness,
    ChildEnvironment,
    EnvClass,
    EnvKey,
    EnvSource,
    EnvironmentPolicyError,
    build_child_environment,
    classify_environment_name,
    parse_name_array,
    purpose_policy,
    resolve_browser_cdp_endpoint,
    resolve_browser_gateway_endpoint,
    verify_browser_cdp_endpoint,
    verify_browser_gateway_endpoint,
    verify_launch_binding_integrity,
)
from rookery.portable.network_policy import ExplicitNetworkPolicy
from rookery.portable.scope import check_url, open_scoped_url
from rookery.portable.scoped_transport import ScopedTransportError
from rookery.portable.util import (
    atomic_write_json,
    canonical_json,
    ensure_private_dir,
    iso_now,
    sha256_bytes,
)

_CSRF_PAGE_DEFAULT = "/challenges"
_CSRF_NONCE_PATTERN = re.compile(r"[\"']?(?:csrf_nonce|csrfNonce)[\"']?\s*(?:=|:)\s*[\"']([A-Za-z0-9_.-]{16,256})[\"']")
_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,512}\Z")
_MAX_IDENTIFIER_BYTES = 256
_GATEWAY_STATUS_MAX_BYTES = 64 * 1024
_CDP_VERSION_MAX_BYTES = 64 * 1024
_TOKEN_SAFE_RESPONSE_HEADERS = frozenset(
    {
        "cache-control",
        "content-length",
        "content-type",
        "date",
        "etag",
        "last-modified",
        "retry-after",
        "server",
        "x-request-id",
    }
)
_TOKEN_SENSITIVE_RESPONSE_HEADERS = frozenset(
    {"authorization", "cookie", "proxy-authorization", "set-cookie", "www-authenticate"}
)
_TOKEN_MAX_SAVED_HEADER_BYTES = 512
_CTFD_NETWORK_SELECTOR = "CTFD_NETWORK_ENV_KEYS"
_CTFD_NETWORK_CLASSES = frozenset(
    {EnvClass.PROXY_CREDENTIAL, EnvClass.CA_TRUST_PATH}
)
_TOKEN_ACCESS_REDIRECT_PATHS = frozenset({"/login"})
_TOKEN_ROUTE_UNAVAILABLE_REASONS = frozenset(
    {
        "scoped_dns_resolution_failed",
        "scoped_tcp_connection_failed",
        "scoped_http_request_failed",
    }
)


class _TokenReadAvailabilityError(RuntimeError):
    """A typed direct-API read failure that may select the sealed browser path."""

    def __init__(self, phase: str, detail: str) -> None:
        super().__init__(f"ctfd_token_read_{phase}_unavailable_{detail}")


def _token_response_headers(headers: Any) -> dict[str, str]:
    """Retain bounded diagnostics while never persisting token-bearing headers."""

    if not headers:
        return {}
    try:
        items = headers.items()
    except AttributeError:
        return {}
    safe: dict[str, str] = {}
    for raw_name, raw_value in items:
        name = str(raw_name).strip().casefold()
        if name in _TOKEN_SENSITIVE_RESPONSE_HEADERS:
            safe[name] = "[redacted]"
            continue
        if name not in _TOKEN_SAFE_RESPONSE_HEADERS:
            continue
        value = str(raw_value).replace("\r", " ").replace("\n", " ").strip()
        encoded = value.encode("utf-8", errors="replace")
        if len(encoded) > _TOKEN_MAX_SAVED_HEADER_BYTES:
            value = encoded[:_TOKEN_MAX_SAVED_HEADER_BYTES].decode("utf-8", errors="ignore") + "…"
        safe[name] = value
    return dict(sorted(safe.items()))


@dataclass(frozen=True)
class _SessionLease:
    """One preflight proof, consumed before any later reviewed attempt."""

    transport: str
    origin: str
    scope_sha256: str
    gateway_boot_nonce: str
    gateway_policy_sha256: str
    gateway_expires_at: str
    account_id: str
    team_id: str | None
    csrf_token: str = field(repr=False)
    expires_at: float = field(repr=False)
    token_fingerprint: str | None = field(default=None, repr=False)
    token_transport_fingerprint: str | None = field(default=None, repr=False)


class _PageCdpChannel:
    """One bounded CDP page connection for the typed scoring state machine.

    The shared CDP module owns the loopback target discovery, network scope,
    WebSocket handshake, and frame codec. This wrapper supplies its narrowly
    typed message interface without exposing a general browser command API.
    """

    def __init__(self, socket: Any) -> None:
        self._socket = socket
        self._stream = socket._stream
        self._next_id = 1

    def send_command(self, method: str, params: dict[str, Any]) -> int:
        identifier = self._next_id
        self._next_id += 1
        payload = json.dumps(
            {"id": identifier, "method": method, "params": params},
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        if len(payload) > _browser_cdp.CDP_MAX_FRAME_BYTES:
            raise BrowserCdpError("browser_cdp_command_invalid")
        _browser_cdp._send_frame(self._stream, 0x1, payload)
        return identifier

    def receive_message(self, timeout_seconds: float) -> dict[str, Any]:
        if not isinstance(timeout_seconds, (float, int)) or timeout_seconds <= 0:
            raise TimeoutError("browser_cdp_timeout")
        self._stream.settimeout(float(timeout_seconds))
        while True:
            try:
                opcode, payload = _browser_cdp._recv_frame(self._stream)
            except TimeoutError:
                raise
            if opcode == 0x8:
                raise EOFError("browser_cdp_websocket_closed")
            if opcode == 0x9:
                _browser_cdp._send_frame(self._stream, 0xA, payload)
                continue
            if opcode != 0x1:
                raise BrowserCdpError("browser_cdp_frame_invalid")
            try:
                message = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise BrowserCdpError("browser_cdp_response_invalid") from exc
            if not isinstance(message, dict):
                raise BrowserCdpError("browser_cdp_response_invalid")
            return message

    def close(self) -> None:
        self._socket.close()


def _open_blank_target_channel(cdp_url: str, target_id: str, timeout_seconds: float) -> _PageCdpChannel:
    """Attach to the newly created blank target before it can navigate."""

    normalized_cdp_url, port = resolve_browser_cdp_endpoint(cdp_url)
    deadline = time.monotonic() + timeout_seconds
    while True:
        targets = _browser_cdp._read_targets(normalized_cdp_url, port)
        candidate = next((item for item in targets if item.get("id") == target_id), None)
        if isinstance(candidate, dict) and candidate.get("type") == "page" and candidate.get("url") == "about:blank":
            websocket_url = _browser_cdp._target_websocket(candidate.get("webSocketDebuggerUrl"), port=port)
            return _PageCdpChannel(_browser_cdp._open_target_socket(websocket_url, port=port))
        if time.monotonic() >= deadline:
            raise BrowserCdpError("browser_cdp_target_missing")
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))


def _browser_websocket_url(cdp_url: str) -> tuple[str, int]:
    """Read Chrome's loopback browser WebSocket without proxy inheritance."""

    normalized_cdp_url, port = resolve_browser_cdp_endpoint(cdp_url)
    scope = _browser_cdp._cdp_scope(port)
    request = urllib.request.Request(
        f"{normalized_cdp_url}/json/version",
        headers={"Accept": "application/json"},
        method="GET",
    )
    try:
        with open_scoped_url(
            scope,
            request,
            timeout=5,
            max_redirects=0,
            transport=_browser_cdp._loopback_transport(scope),
        ) as response:
            if getattr(response, "status", None) != 200:
                raise BrowserCdpError("browser_cdp_version_invalid")
            content_type = str(response.headers.get("Content-Type", "")).split(";", 1)[0]
            if content_type.strip().casefold() != "application/json":
                raise BrowserCdpError("browser_cdp_version_invalid")
            raw = response.read(_CDP_VERSION_MAX_BYTES + 1)
    except BrowserCdpError:
        raise
    except (OSError, RuntimeError, TimeoutError) as exc:
        raise BrowserCdpError("browser_cdp_version_unavailable") from exc
    if not isinstance(raw, bytes) or len(raw) > _CDP_VERSION_MAX_BYTES:
        raise BrowserCdpError("browser_cdp_version_invalid")
    try:
        document = json.loads(raw.decode("utf-8"))
        websocket_url = document["webSocketDebuggerUrl"]
        parsed = urllib.parse.urlsplit(websocket_url)
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise BrowserCdpError("browser_cdp_version_invalid") from exc
    if (
        not isinstance(websocket_url, str)
        or parsed.scheme.casefold() != "ws"
        or parsed.hostname != "127.0.0.1"
        or parsed.port != port
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.path.startswith("/devtools/browser/")
        or len(parsed.path) == len("/devtools/browser/")
        or parsed.query
        or parsed.fragment
    ):
        raise BrowserCdpError("browser_cdp_version_invalid")
    return websocket_url, port


class _BrowserTargetController:
    """Bounded browser-level lifecycle for one adapter-owned quiet target."""

    _METHODS = frozenset({"Target.closeTarget", "Target.createTarget", "Target.getTargets"})

    def __init__(self, channel: _PageCdpChannel) -> None:
        self._channel = channel

    def _command(self, method: str, params: dict[str, Any], timeout_seconds: float) -> dict[str, Any]:
        if method not in self._METHODS or timeout_seconds <= 0:
            raise BrowserCdpError("browser_cdp_command_forbidden")
        identifier = self._channel.send_command(method, params)
        deadline = time.monotonic() + timeout_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BrowserCdpError("browser_cdp_timeout")
            try:
                message = self._channel.receive_message(remaining)
            except TimeoutError as exc:
                raise BrowserCdpError("browser_cdp_timeout") from exc
            except (EOFError, OSError) as exc:
                raise BrowserCdpError("browser_cdp_disconnected") from exc
            if message.get("id") == identifier:
                result = message.get("result")
                if "error" in message or not isinstance(result, dict):
                    raise BrowserCdpError("browser_cdp_response_invalid")
                return result
            if message.get("method") not in {
                "Target.targetCreated",
                "Target.targetDestroyed",
                "Target.targetInfoChanged",
            }:
                raise BrowserCdpError("browser_cdp_response_invalid")

    def create_blank_target(self, timeout_seconds: float) -> str:
        result = self._command(
            "Target.createTarget",
            {"url": "about:blank"},
            timeout_seconds,
        )
        target_id = result.get("targetId")
        if not isinstance(target_id, str) or not _IDENTIFIER.fullmatch(target_id):
            raise BrowserCdpError("browser_target_binding_mismatch")
        return target_id

    def close_target(self, target_id: str, timeout_seconds: float) -> bool:
        if not isinstance(target_id, str) or not _IDENTIFIER.fullmatch(target_id):
            return False
        closed = self._command("Target.closeTarget", {"targetId": target_id}, timeout_seconds)
        if closed.get("success") is not True:
            return False
        targets = self._command("Target.getTargets", {}, timeout_seconds).get("targetInfos")
        return isinstance(targets, list) and all(
            not isinstance(item, dict) or item.get("targetId") != target_id for item in targets
        )


@dataclass
class _OwnedTarget:
    """One quiet browser target that the shared state machine must close first."""

    browser: _PageCdpChannel
    page: _PageCdpChannel
    controller: _BrowserTargetController
    target_id: str
    binding: BrowserScoringBinding | None = None
    account_document: dict[str, Any] | None = field(default=None, repr=False)
    closed: bool = False

    def close(self, target_id: str, timeout_seconds: float) -> bool:
        if target_id != self.target_id or self.closed:
            return False
        self.closed = self.controller.close_target(target_id, timeout_seconds)
        return self.closed

    def dispose(self) -> None:
        if not self.closed:
            try:
                self.closed = self.controller.close_target(self.target_id, 2.0)
            except BrowserCdpError:
                self.closed = False
        if not self.closed:
            _RETAINED_UNCLOSED_TARGETS.append(self)
            return
        self.page.close()
        self.browser.close()


# Detaching from a target with Fetch still armed can release a paused request.
# Keep a failed-to-close target connected until the process exits or the
# operator tears down the dedicated browser, rather than triggering detach.
_RETAINED_UNCLOSED_TARGETS: list[_OwnedTarget] = []


def _open_owned_target(
    cdp_url: str,
    origin: str,
    gateway_policy_sha256: str,
    timeout_seconds: float,
) -> _OwnedTarget:
    """Create and bind a quiet target without touching the operator auth page."""

    websocket_url, port = _browser_websocket_url(cdp_url)
    browser = _PageCdpChannel(_browser_cdp._open_target_socket(websocket_url, port=port))
    controller = _BrowserTargetController(browser)
    page: _PageCdpChannel | None = None
    target_id: str | None = None
    owned: _OwnedTarget | None = None
    try:
        target_id = controller.create_blank_target(timeout_seconds)
        page = _open_blank_target_channel(cdp_url, target_id, timeout_seconds)
        owned = _OwnedTarget(browser, page, controller, target_id)
        bootstrap = bootstrap_owned_browser_target(
            page,
            origin,
            gateway_policy_sha256,
            owned_target_id=target_id,
            close_owned_target=owned.close,
            timeout_seconds=timeout_seconds,
        )
        owned.binding = bootstrap.binding
        owned.account_document = bootstrap.account_document
        return owned
    except BaseException:
        if owned is not None:
            owned.dispose()
        elif target_id is not None:
            try:
                if controller.close_target(target_id, 2.0):
                    if page is not None:
                        page.close()
                    browser.close()
            except BrowserCdpError:
                pass
        else:
            browser.close()
        raise


def _unhealthy_capabilities(detail: str) -> list[CapabilityHealth]:
    return [
        CapabilityHealth("platform_inventory", "available", "unhealthy", "stale", "read-only", (), detail),
        CapabilityHealth("challenge_details", "available", "unhealthy", "stale", "read-only", (), detail),
        CapabilityHealth("scoring", "available", "unhealthy", "stale", "reviewer-only", ("flag", "free_text"), detail),
    ]


class CTFdBrowserGatewayAdapter(Adapter):
    """CTFd adapter whose only platform path is a sealed Chrome gateway context."""

    id = "ctfd_browser_gateway"

    def __init__(self, root: Path, manifest: dict[str, Any], scope: dict[str, Any]):
        super().__init__(root, manifest, scope)
        self._lease: _SessionLease | None = None

    def _positive_int(self, name: str, default: int, maximum: int) -> int:
        value = self.config.get(name, default)
        if isinstance(value, bool):
            raise RuntimeError(f"browser gateway {name} must be an integer")
        try:
            resolved = int(value)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"browser gateway {name} must be an integer") from exc
        if not 1 <= resolved <= maximum:
            raise RuntimeError(f"browser gateway {name} is outside supported range")
        return resolved

    def _timeout(self) -> float:
        return float(self._positive_int("timeout", 30, 120))

    def _response_limit(self) -> int:
        return self._positive_int("max_response_bytes", DEFAULT_ADAPTER_OUTPUT_BYTES, MAX_ADAPTER_OUTPUT_BYTES)

    def _browser_response_limit(self) -> int:
        """Keep every CDP state-machine response inside its fixed maximum."""

        return min(self._response_limit(), 1024 * 1024)

    def _lease_seconds(self) -> int:
        return self._positive_int("session_lease_seconds", 60, 300)

    @staticmethod
    def _required_identifier(value: object, *, label: str) -> str:
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise RuntimeError(f"browser gateway {label} is required")
        identifier = str(value)
        if (
            not identifier
            or len(identifier.encode("utf-8")) > _MAX_IDENTIFIER_BYTES
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in identifier)
        ):
            raise RuntimeError(f"browser gateway {label} is invalid")
        return identifier

    def _scoring_mode(self) -> str:
        mode = self.config.get("scoring_mode")
        if mode not in {"user", "team"}:
            raise RuntimeError("browser gateway scoring_mode must be user or team")
        return str(mode)

    def _expected_team_id(self, mode: str) -> str | None:
        value = self.config.get("expected_team_id")
        if mode == "user":
            if value not in {None, "", "unknown"}:
                raise RuntimeError("browser gateway expected_team_id requires scoring_mode team")
            return None
        return self._required_identifier(value, label="expected_team_id")

    def _csrf_page_path(self) -> str:
        path = self.config.get("csrf_page_path", _CSRF_PAGE_DEFAULT)
        if not isinstance(path, str) or not re.fullmatch(r"/[A-Za-z0-9/_-]{0,255}", path) or "//" in path:
            raise RuntimeError("browser gateway csrf_page_path is invalid")
        return path

    def _token_configuration(self) -> tuple[str, Any, str]:
        """Resolve the token and its declared direct transport without I/O.

        The selected adapter always declares this credential.  A missing token
        is therefore a configuration failure, rather than an invitation to
        silently use the browser session under a different identity.
        """

        configured = self.config.get("token_env", "CTFD_TOKEN")
        if not isinstance(configured, str) or not configured:
            raise RuntimeError("ctfd_token_configuration_invalid")
        try:
            token_class = classify_environment_name(configured)
        except EnvironmentPolicyError as exc:
            raise RuntimeError("ctfd_token_configuration_invalid") from exc
        if token_class not in {EnvClass.ADAPTER_SECRET, EnvClass.UNKNOWN_EXPLICIT}:
            raise RuntimeError("ctfd_token_configuration_invalid")
        try:
            resolved = self._resolve_local_environment(
                (
                    EnvKey(
                        configured,
                        token_class,
                        required=True,
                        sources=(EnvSource.DOTENV, EnvSource.PARENT),
                    ),
                    EnvKey(
                        _CTFD_NETWORK_SELECTOR,
                        EnvClass.ROOKERY_CONFIG,
                        sources=(EnvSource.DOTENV, EnvSource.PARENT),
                    ),
                )
            )
            network_names = parse_name_array(
                resolved.get(_CTFD_NETWORK_SELECTOR, ""),
                label=_CTFD_NETWORK_SELECTOR,
            )
            declarations: list[EnvKey] = []
            for name in network_names:
                classification = classify_environment_name(name)
                if classification not in _CTFD_NETWORK_CLASSES:
                    raise EnvironmentPolicyError("ctfd_network_configuration_invalid")
                declarations.append(
                    EnvKey(
                        name,
                        classification,
                        required=True,
                        sources=(EnvSource.DOTENV, EnvSource.PARENT),
                    )
                )
            network_environment = build_child_environment(
                self.root,
                policy=purpose_policy(
                    "ctfd-browser-gateway-token-network",
                    declarations,
                    allowed_classes=_CTFD_NETWORK_CLASSES,
                ),
            )
            transport = ExplicitNetworkPolicy.from_child_environment(
                network_environment
            ).scoped_transport(self.scope, platform=True)
        except (EnvironmentPolicyError, RuntimeError, TypeError, ValueError) as exc:
            raise RuntimeError("ctfd_token_configuration_invalid") from exc
        token = str(resolved.get(configured) or "")
        if not token or any(ord(character) < 0x20 or ord(character) == 0x7F for character in token):
            raise RuntimeError("ctfd_token_configuration_invalid")
        binding = sha256_bytes(
            canonical_json(
                {
                    "token_env": configured,
                    "network_environment": network_environment.values,
                }
            ).encode("utf-8")
        )
        return token, transport, binding

    def _token_request(
        self,
        origin: str,
        token: str,
        path: str,
        *,
        phase: str,
    ) -> urllib.request.Request:
        url = origin + path
        decision = check_url(self.scope, url, platform=True)
        if not decision.allowed:
            raise RuntimeError("ctfd_token_scope_denied")
        return urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "Authorization": f"Token {token}",
            },
            method="GET",
        )

    @staticmethod
    def _token_status(response: Any, phase: str) -> int:
        status = getattr(response, "status", None)
        if not isinstance(status, int) or isinstance(status, bool):
            try:
                status = response.getcode()
            except AttributeError as exc:
                raise RuntimeError(f"ctfd_token_read_{phase}_protocol_invalid") from exc
        if not isinstance(status, int) or isinstance(status, bool):
            raise RuntimeError(f"ctfd_token_read_{phase}_protocol_invalid")
        return status

    @staticmethod
    def _token_content_type(response: Any) -> str:
        headers = getattr(response, "headers", None)
        try:
            value = headers.get("Content-Type") if headers else ""
        except AttributeError:
            value = ""
        return str(value).split(";", 1)[0].strip().casefold()

    @staticmethod
    def _token_redirect_classification(
        response: Any,
        *,
        phase: str,
        origin: str,
        requested_url: str,
    ) -> tuple[bool, bool]:
        """Prove the final response stays on the CTFd origin before fallback."""

        try:
            response_url = response.geturl()
        except AttributeError:
            response_url = requested_url
        if not isinstance(response_url, str):
            raise RuntimeError(f"ctfd_token_read_{phase}_protocol_invalid")
        try:
            parsed_response = urllib.parse.urlsplit(response_url)
            redirected_origin = canonical_gateway_origin(
                f"{parsed_response.scheme}://{parsed_response.netloc}"
            )
        except (BrowserGatewayPolicyError, ValueError) as exc:
            raise RuntimeError(f"ctfd_token_read_{phase}_protocol_invalid") from exc
        if redirected_origin != origin:
            raise RuntimeError(f"ctfd_token_read_{phase}_redirect_origin_invalid")
        redirected = response_url != requested_url
        return redirected, redirected and parsed_response.path in _TOKEN_ACCESS_REDIRECT_PATHS

    def _token_document(
        self,
        response: Any,
        *,
        phase: str,
        origin: str,
        requested_url: str,
    ) -> dict[str, Any]:
        status = self._token_status(response, phase)
        redirected, access_redirect = self._token_redirect_classification(
            response,
            phase=phase,
            origin=origin,
            requested_url=requested_url,
        )
        if status in {401, 403}:
            if redirected and not access_redirect:
                raise RuntimeError(f"ctfd_token_read_{phase}_redirect_unrecognized")
            raise _TokenReadAvailabilityError(phase, f"http_{status}")
        if not 200 <= status < 300:
            raise RuntimeError(f"ctfd_token_read_{phase}_platform_http_{status}")
        content_type = self._token_content_type(response)
        if content_type == "text/html":
            try:
                bounded_response_bytes(response, self._response_limit())
            except RuntimeError as exc:
                raise RuntimeError(f"ctfd_token_read_{phase}_protocol_invalid") from exc
            raise _TokenReadAvailabilityError(phase, "html_interstitial")
        if access_redirect:
            raise _TokenReadAvailabilityError(phase, "same_origin_access_redirect")
        if redirected:
            raise RuntimeError(f"ctfd_token_read_{phase}_redirect_unrecognized")
        if content_type != "application/json":
            raise RuntimeError(f"ctfd_token_read_{phase}_protocol_invalid")
        try:
            raw = bounded_response_bytes(response, self._response_limit())
            document = _bounded_json_document(
                raw,
                error=f"ctfd_token_read_{phase}_protocol_invalid",
            )
        except (RuntimeError, BrowserCdpScoringError) as exc:
            raise RuntimeError(f"ctfd_token_read_{phase}_protocol_invalid") from exc
        if not isinstance(document, dict) or document.get("success") is not True:
            raise RuntimeError(f"ctfd_token_read_{phase}_protocol_invalid")
        return document

    def _token_get(
        self,
        origin: str,
        token: str,
        transport: Any,
        *,
        path: str,
        phase: str,
    ) -> dict[str, Any]:
        request = self._token_request(origin, token, path, phase=phase)
        try:
            with open_scoped_url(
                self.scope,
                request,
                timeout=self._timeout(),
                platform=True,
                max_redirects=1,
                transport=transport,
            ) as response:
                return self._token_document(
                    response,
                    phase=phase,
                    origin=origin,
                    requested_url=request.full_url,
                )
        except _TokenReadAvailabilityError:
            raise
        except urllib.error.HTTPError as exc:
            redirected, access_redirect = self._token_redirect_classification(
                exc,
                phase=phase,
                origin=origin,
                requested_url=request.full_url,
            )
            if exc.code in {401, 403}:
                if redirected and not access_redirect:
                    raise RuntimeError(f"ctfd_token_read_{phase}_redirect_unrecognized") from exc
                raise _TokenReadAvailabilityError(phase, f"http_{exc.code}") from exc
            raise RuntimeError(f"ctfd_token_read_{phase}_platform_http_{exc.code}") from exc
        except ScopedTransportError as exc:
            if str(exc) in _TOKEN_ROUTE_UNAVAILABLE_REASONS:
                raise _TokenReadAvailabilityError(phase, "route_unavailable") from exc
            raise RuntimeError(f"ctfd_token_read_{phase}_transport_invalid") from exc
        except ssl.SSLError as exc:
            raise RuntimeError(f"ctfd_token_read_{phase}_tls_invalid") from exc
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, ssl.SSLError):
                raise RuntimeError(f"ctfd_token_read_{phase}_tls_invalid") from exc
            if isinstance(reason, (OSError, TimeoutError)):
                raise _TokenReadAvailabilityError(phase, "route_unavailable") from exc
            raise RuntimeError(f"ctfd_token_read_{phase}_route_invalid") from exc
        except (OSError, TimeoutError) as exc:
            raise _TokenReadAvailabilityError(phase, "route_unavailable") from exc

    def _token_identifier(self, document: dict[str, Any], *, phase: str) -> str:
        data = document.get("data")
        identifier = data.get("id") if isinstance(data, dict) else None
        try:
            return self._required_identifier(identifier, label=f"token_{phase}_id")
        except RuntimeError as exc:
            raise RuntimeError(f"ctfd_token_read_{phase}_protocol_invalid") from exc

    def _token_inventory(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        challenges = document.get("data")
        if not isinstance(challenges, list) or not all(
            isinstance(challenge, dict) for challenge in challenges
        ):
            raise RuntimeError("ctfd_token_read_inventory_protocol_invalid")
        return challenges

    def _token_preflight(
        self,
        origin: str,
        token: str,
        transport: Any,
        *,
        mode: str,
        expected_account: str,
        expected_team: str | None,
    ) -> tuple[str, str | None, list[dict[str, Any]]]:
        account_document = self._token_get(
            origin,
            token,
            transport,
            path="/api/v1/users/me",
            phase="account",
        )
        account_id = self._token_identifier(account_document, phase="account")
        if account_id != expected_account:
            raise RuntimeError("ctfd_token_identity_mismatch")
        team_id: str | None = None
        if mode == "team":
            team_document = self._token_get(
                origin,
                token,
                transport,
                path="/api/v1/teams/me",
                phase="team",
            )
            team_id = self._token_identifier(team_document, phase="team")
            if team_id != expected_team:
                raise RuntimeError("ctfd_token_identity_mismatch")
            account_data = account_document.get("data")
            account_team = account_data.get("team_id") if isinstance(account_data, dict) else None
            if account_team is not None:
                try:
                    account_team_id = self._required_identifier(
                        account_team, label="token_account_team_id"
                    )
                except RuntimeError as exc:
                    raise RuntimeError("ctfd_token_read_account_protocol_invalid") from exc
                if account_team_id != team_id:
                    raise RuntimeError("ctfd_token_identity_mismatch")
        inventory = self._token_get(
            origin,
            token,
            transport,
            path="/api/v1/challenges",
            phase="inventory",
        )
        return account_id, team_id, self._token_inventory(inventory)

    def _endpoints(self) -> tuple[str, str, str | None]:
        resolved = self._resolve_local_environment(
            (
                EnvKey("CTFD_URL", EnvClass.ROOKERY_CONFIG, sources=(EnvSource.DOTENV, EnvSource.PARENT)),
                EnvKey(
                    "BROWSER_CDP_URL",
                    EnvClass.ROOKERY_CONFIG,
                    required=True,
                    sources=(EnvSource.DOTENV, EnvSource.PARENT),
                ),
                EnvKey(
                    "BROWSER_GATEWAY_URL",
                    EnvClass.ROOKERY_CONFIG,
                    required=True,
                    sources=(EnvSource.DOTENV, EnvSource.PARENT),
                ),
            )
        )
        return (
            str(resolved.get("BROWSER_CDP_URL") or ""),
            str(resolved.get("BROWSER_GATEWAY_URL") or ""),
            str(resolved.get("CTFD_URL") or "").strip() or None,
        )

    def _gateway_identity(
        self, gateway_url: str, environment_origin: str | None, *, boot_nonce: str | None = None
    ) -> tuple[str, BrowserGatewayReadiness]:
        binding = verify_launch_binding_integrity(self.root)
        if binding.record.get("selected_adapter") != self.id:
            raise RuntimeError("browser gateway launch binding adapter mismatch")
        origin = browser_gateway_origin(self.manifest, environment_origin)
        if environment_origin and canonical_gateway_origin(environment_origin) != origin:
            raise RuntimeError("browser gateway CTFd origin does not match selected adapter origin")
        policy = compile_browser_gateway_policy(
            self.manifest,
            baseline_configuration_digest=str(binding.record["baseline_configuration_digest"]),
            origin=origin,
            environment_origin=environment_origin,
        )
        if policy.get("scope_sha256") != scope_sha256(self.scope):
            raise RuntimeError("browser_gateway_scope_binding_changed")
        digest = policy_sha256(policy)
        expires_at = policy.get("expires_at")
        if not isinstance(expires_at, str):
            raise RuntimeError("browser_gateway_policy_invalid")
        readiness = verify_browser_gateway_endpoint(
            gateway_url,
            expected_policy_sha256=digest,
            expected_expires_at=expires_at,
            expected_boot_nonce=boot_nonce,
        )
        return origin, readiness

    @staticmethod
    def _gateway_status_scope(port: int) -> dict[str, Any]:
        """Build the one loopback authority used to observe gateway counters."""

        return {
            "acknowledged": True,
            "generation": 0,
            "expires_at": "unknown",
            "allowed_hosts": ["127.0.0.1"],
            "allowed_cidrs": ["127.0.0.1/32"],
            "allowed_ports": [port],
            "allowed_protocols": ["http"],
            "allowed_file_origins": [],
            "platform_hosts": [],
            "max_attachment_bytes": 0,
        }

    def _gateway_counters(self, gateway_url: str, expected: BrowserGatewayReadiness) -> dict[str, int]:
        """Read value-free gateway counters through a fresh direct loopback scope.

        ``verify_browser_gateway_endpoint`` has already schema-checked the
        service. This second fixed status read corroborates gateway activity
        during the exact Chrome request without turning the status endpoint
        into a general HTTP client.
        """

        base_url, status_port = resolve_browser_gateway_endpoint(gateway_url)
        scope = self._gateway_status_scope(status_port)
        transport = ExplicitNetworkPolicy.from_child_environment(
            ChildEnvironment({}, "browser-gateway-counter-loopback", ())
        ).scoped_transport(scope)
        request = urllib.request.Request(f"{base_url}/status", headers={"Accept": "application/json"}, method="GET")
        try:
            with open_scoped_url(
                scope,
                request,
                timeout=3,
                max_redirects=0,
                transport=transport,
            ) as response:
                if getattr(response, "status", None) != 200:
                    raise RuntimeError("browser_gateway_unavailable")
                content_type = str(response.headers.get("Content-Type", "")).split(";", 1)[0]
                if content_type.strip().casefold() != "application/json":
                    raise RuntimeError("browser_gateway_invalid_response")
                raw = response.read(_GATEWAY_STATUS_MAX_BYTES + 1)
        except RuntimeError:
            raise
        except (OSError, TimeoutError) as exc:
            raise RuntimeError("browser_gateway_unavailable") from exc
        if not isinstance(raw, bytes) or len(raw) > _GATEWAY_STATUS_MAX_BYTES:
            raise RuntimeError("browser_gateway_response_too_large")
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("browser_gateway_invalid_response") from exc
        listeners = document.get("listeners") if isinstance(document, dict) else None
        counters = document.get("counters") if isinstance(document, dict) else None
        if (
            not isinstance(document, dict)
            or document.get("schema_version") != "1"
            or document.get("boot_nonce") != expected.boot_nonce
            or document.get("policy_sha256") != expected.policy_sha256
            or document.get("expires_at") != expected.expires_at
            or not isinstance(listeners, dict)
            or listeners.get("proxy") != f"127.0.0.1:{expected.proxy_port}"
            or listeners.get("status") != f"127.0.0.1:{expected.status_port}"
            or not isinstance(counters, dict)
            or set(counters) != {"accepted", "refused", "connected", "completed", "failed", "bytes"}
            or any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counters.values())
        ):
            raise RuntimeError("browser_gateway_policy_mismatch")
        return {"connected": counters["connected"], "bytes": counters["bytes"]}

    @staticmethod
    def _require_gateway_transfer(before: dict[str, int], after: dict[str, int]) -> None:
        """Fail closed when the dedicated gateway observed no opaque transfer."""

        if after["bytes"] <= before["bytes"]:
            raise RuntimeError("browser_context_proxy_unverified")

    @staticmethod
    def _response_identifier(
        document: dict[str, Any], *, label: str, field: str = "id"
    ) -> str:
        if document.get("success") is not True:
            raise RuntimeError(f"browser gateway invalid CTFd {label} response")
        data = document.get("data")
        identifier = data.get(field) if isinstance(data, dict) else None
        if isinstance(identifier, bool) or not isinstance(identifier, (int, str)):
            raise RuntimeError(f"browser gateway invalid CTFd {label} response")
        value = str(identifier)
        if not value or len(value.encode("utf-8")) > _MAX_IDENTIFIER_BYTES:
            raise RuntimeError(f"browser gateway invalid CTFd {label} response")
        return value

    @staticmethod
    def _csrf_token(text: str | None) -> str:
        if not isinstance(text, str):
            raise RuntimeError("browser gateway invalid CTFd CSRF response")
        matches = set(_CSRF_NONCE_PATTERN.findall(text))
        if len(matches) != 1:
            raise RuntimeError("browser gateway CTFd CSRF nonce is missing or ambiguous")
        return next(iter(matches))

    @staticmethod
    def _inventory(document: dict[str, Any]) -> list[dict[str, Any]]:
        if document.get("success") is not True:
            raise RuntimeError("browser gateway invalid CTFd inventory response")
        challenges = document.get("data")
        if (
            not isinstance(challenges, list)
            or not challenges
            or not all(isinstance(challenge, dict) for challenge in challenges)
        ):
            raise RuntimeError("browser gateway inventory is empty or invalid")
        return challenges

    def _read(
        self,
        cdp_url: str,
        origin: str,
        gateway_policy_sha256: str,
        *,
        operation: str,
    ):
        """Run one fixed browser read in a fresh target and close it while armed."""

        owned = _open_owned_target(
            cdp_url,
            origin,
            gateway_policy_sha256,
            self._timeout(),
        )
        try:
            binding = owned.binding
            if binding is None:
                raise RuntimeError("browser gateway owned target binding is unavailable")
            request = CTFdReadOnlyRequest(
                binding=binding,
                operation=operation,
                csrf_page_path=self._csrf_page_path(),
                timeout_seconds=self._timeout(),
                max_response_bytes=self._browser_response_limit(),
            )
            return execute_ctfd_browser_read(
                owned.page,
                request,
                close_owned_target=owned.close,
            )
        finally:
            owned.dispose()

    def _browser_preflight(
        self,
        cdp_url: str,
        gateway_url: str,
        environment_origin: str | None,
        origin: str,
        gateway: BrowserGatewayReadiness,
        *,
        mode: str,
        expected_account: str,
        expected_team: str | None,
    ) -> tuple[str, str | None, str, list[dict[str, Any]]]:
        """Establish the existing isolated Chrome proof after token-read failure."""

        gateway_before = self._gateway_counters(gateway_url, gateway)
        account = self._read(
            cdp_url,
            origin,
            gateway.policy_sha256,
            operation="account",
        )
        gateway_after_account = self._gateway_counters(gateway_url, gateway)
        self._require_gateway_transfer(gateway_before, gateway_after_account)
        account_id = self._response_identifier(account.document or {}, label="account")
        if account_id != expected_account:
            raise RuntimeError("browser gateway CTFd account does not match expected account")
        team_id: str | None = None
        if mode == "team":
            team = self._read(
                cdp_url,
                origin,
                gateway.policy_sha256,
                operation="team",
            )
            team_id = self._response_identifier(team.document or {}, label="team")
            if team_id != expected_team:
                raise RuntimeError("browser gateway CTFd team does not match expected team")
        csrf = self._read(
            cdp_url,
            origin,
            gateway.policy_sha256,
            operation="csrf",
        )
        csrf_token = self._csrf_token(csrf.text)
        inventory = self._read(
            cdp_url,
            origin,
            gateway.policy_sha256,
            operation="inventory",
        )
        challenges = self._inventory(inventory.document or {})
        # The final status check binds this short-lived lease to one gateway boot.
        _origin, current_gateway = self._gateway_identity(
            gateway_url,
            environment_origin,
            boot_nonce=gateway.boot_nonce,
        )
        if (
            current_gateway.policy_sha256 != gateway.policy_sha256
            or current_gateway.expires_at != gateway.expires_at
        ):
            raise RuntimeError("browser_gateway_session_binding_changed")
        return account_id, team_id, csrf_token, challenges

    def _new_lease(self) -> tuple[_SessionLease, list[dict[str, Any]]]:
        mode = self._scoring_mode()
        expected_account = self._required_identifier(
            self.config.get("expected_account_id"), label="expected_account_id"
        )
        expected_team = self._expected_team_id(mode)
        cdp_url, gateway_url, environment_origin = self._endpoints()
        # The fallback is an authorized but sealed capability.  Prove it first
        # even when the direct token reads eventually succeed.
        verify_browser_cdp_endpoint(cdp_url)
        origin, gateway = self._gateway_identity(gateway_url, environment_origin)
        semantic_scope_sha256 = scope_sha256(self.scope)
        token, token_transport, token_transport_fingerprint = self._token_configuration()
        try:
            account_id, team_id, challenges = self._token_preflight(
                origin,
                token,
                token_transport,
                mode=mode,
                expected_account=expected_account,
                expected_team=expected_team,
            )
        except _TokenReadAvailabilityError:
            account_id, team_id, csrf_token, challenges = self._browser_preflight(
                cdp_url,
                gateway_url,
                environment_origin,
                origin,
                gateway,
                mode=mode,
                expected_account=expected_account,
                expected_team=expected_team,
            )
            selected_transport = "browser_gateway"
            token_fingerprint: str | None = None
            token_transport_fingerprint: str | None = None
        else:
            csrf_token = ""
            selected_transport = "token"
            token_fingerprint = sha256_bytes(token.encode("utf-8"))
        # The final status check binds each one-use lease, including a token
        # lease, to one prepared gateway boot and policy.
        _origin, current_gateway = self._gateway_identity(
            gateway_url,
            environment_origin,
            boot_nonce=gateway.boot_nonce,
        )
        if _origin != origin:
            raise RuntimeError("browser_gateway_session_binding_changed")
        return (
            _SessionLease(
                transport=selected_transport,
                origin=origin,
                scope_sha256=semantic_scope_sha256,
                gateway_boot_nonce=current_gateway.boot_nonce,
                gateway_policy_sha256=current_gateway.policy_sha256,
                gateway_expires_at=current_gateway.expires_at,
                account_id=account_id,
                team_id=team_id,
                csrf_token=csrf_token,
                expires_at=time.monotonic() + self._lease_seconds(),
                token_fingerprint=token_fingerprint,
                token_transport_fingerprint=token_transport_fingerprint,
            ),
            challenges,
        )

    def sync(self) -> dict[str, Any]:
        self._lease = None
        try:
            lease, challenges = self._new_lease()
        except (
            BrowserCdpError,
            BrowserCdpScoringError,
            BrowserGatewayPolicyError,
            EnvironmentPolicyError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
            return normalized_snapshot(self.id, _unhealthy_capabilities(str(exc)), [])
        self._lease = lease
        health = "degraded" if lease.transport == "browser_gateway" else "healthy"
        detail = (
            "token_primary_unavailable; browser_fallback_ready"
            if lease.transport == "browser_gateway"
            else ""
        )
        capabilities = [
            CapabilityHealth("platform_inventory", "available", health, iso_now(), "read-only", (), detail),
            CapabilityHealth("challenge_details", "available", health, iso_now(), "read-only", (), detail),
            CapabilityHealth("release_changes", "available", health, iso_now(), "read-only", (), detail),
            CapabilityHealth("scoring", "available", health, iso_now(), "reviewer-only", ("flag",), detail),
        ]
        return normalized_snapshot(self.id, capabilities, challenges)

    def _current_lease(self) -> _SessionLease:
        lease = self._lease
        self._lease = None
        if lease is None or time.monotonic() >= lease.expires_at:
            raise RuntimeError("browser gateway session lease is unavailable or expired")
        return lease

    def _token_submission(
        self,
        lease: _SessionLease,
        challenge_id: int,
        candidate: str,
        evidence_root: Path,
    ) -> dict[str, Any]:
        """Release one direct CTFd attempt without any failover path.

        Once ``open_scoped_url`` is entered, urllib cannot prove whether bytes
        reached CTFd. Every later exception is consequently recorded as an
        indeterminate, potentially committed attempt by the generic executor.
        """

        token, transport, transport_fingerprint = self._token_configuration()
        if (
            lease.token_fingerprint is None
            or lease.token_transport_fingerprint is None
            or not hmac.compare_digest(
                lease.token_fingerprint,
                sha256_bytes(token.encode("utf-8")),
            )
            or not hmac.compare_digest(
                lease.token_transport_fingerprint,
                transport_fingerprint,
            )
        ):
            raise RuntimeError("ctfd_token_lease_binding_changed")
        body = json.dumps(
            {"challenge_id": challenge_id, "submission": candidate},
            separators=(",", ":"),
        ).encode("utf-8")
        url = lease.origin + "/api/v1/challenges/attempt"
        decision = check_url(self.scope, url, platform=True)
        if not decision.allowed:
            raise RuntimeError("ctfd_token_scope_denied")
        request = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Accept": "application/json",
                "Authorization": f"Token {token}",
                "Content-Type": "application/json",
            },
        )
        try:
            transport.preflight_url(request.full_url)
        except Exception as exc:
            raise RuntimeError("ctfd_token_post_transport_not_admitted") from exc
        response_path = evidence_root / "response.json"
        try:
            with open_scoped_url(
                self.scope,
                request,
                timeout=self._timeout(),
                platform=True,
                max_redirects=0,
                transport=transport,
            ) as response:
                status = self._token_status(response, "post")
                headers = _token_response_headers(getattr(response, "headers", None))
                raw = bounded_response_bytes(response, self._response_limit())
        except urllib.error.HTTPError as exc:
            status = exc.code
            headers = _token_response_headers(exc.headers)
            try:
                raw = bounded_response_bytes(exc, self._response_limit())
            except RuntimeError as read_exc:
                atomic_write_json(
                    response_path,
                    {"transport": "token", "phase": "ctfd_token_post_response_invalid"},
                    mode=0o600,
                )
                raise RuntimeError("ctfd_token_post_response_invalid") from read_exc
        except Exception as exc:
            atomic_write_json(
                response_path,
                {"transport": "token", "phase": "ctfd_token_post_indeterminate"},
                mode=0o600,
            )
            raise RuntimeError("ctfd_token_post_indeterminate") from exc
        if 200 <= status < 300:
            content_type = headers.get("content-type", "").split(";", 1)[0].casefold()
            if content_type != "application/json":
                atomic_write_json(
                    response_path,
                    {
                        "http_status": status,
                        "headers": headers,
                        "transport": "token",
                        "phase": "ctfd_token_post_response_invalid",
                    },
                    mode=0o600,
                )
                raise RuntimeError("ctfd_token_post_response_invalid")
            try:
                document = _bounded_json_document(
                    raw,
                    error="ctfd_token_post_response_invalid",
                )
            except BrowserCdpScoringError as exc:
                atomic_write_json(
                    response_path,
                    {
                        "http_status": status,
                        "headers": headers,
                        "transport": "token",
                        "phase": "ctfd_token_post_response_invalid",
                    },
                    mode=0o600,
                )
                raise RuntimeError("ctfd_token_post_response_invalid") from exc
            if not isinstance(document.get("success"), bool):
                atomic_write_json(
                    response_path,
                    {
                        "http_status": status,
                        "headers": headers,
                        "transport": "token",
                        "phase": "ctfd_token_post_response_invalid",
                    },
                    mode=0o600,
                )
                raise RuntimeError("ctfd_token_post_response_invalid")
        else:
            try:
                document = _bounded_json_document(
                    raw,
                    error="ctfd_token_post_response_invalid",
                )
            except BrowserCdpScoringError:
                document = {}
        response_obj = {
            "http_status": status,
            "headers": headers,
            "data": document,
            "transport": "token",
        }
        atomic_write_json(response_path, response_obj, mode=0o600)
        verdict = parse_ctfd_attempt_verdict(
            response_obj,
            http_status=status,
        )
        return {
            "response": response_obj,
            "response_path": str(response_path),
            "verdict": verdict.to_dict(),
        }

    def _browser_submission(
        self,
        lease: _SessionLease,
        cdp_url: str,
        gateway_url: str,
        origin: str,
        gateway: BrowserGatewayReadiness,
        challenge_id: int,
        candidate: str,
        evidence_root: Path,
    ) -> dict[str, Any]:
        """Preserve the existing fresh-target one-POST browser mutation path."""

        gateway_before = self._gateway_counters(gateway_url, gateway)
        owned = _open_owned_target(
            cdp_url,
            origin,
            lease.gateway_policy_sha256,
            self._timeout(),
        )
        try:
            binding = owned.binding
            if binding is None:
                raise RuntimeError("browser gateway owned target binding is unavailable")
            fresh_account = self._response_identifier(owned.account_document or {}, label="account")
            expected_account = self._required_identifier(
                self.config.get("expected_account_id"), label="expected_account_id"
            )
            if fresh_account != lease.account_id or fresh_account != expected_account:
                raise RuntimeError("browser gateway CTFd account changed since preflight")
            mode = self._scoring_mode()
            if mode == "team":
                fresh_team = self._response_identifier(
                    owned.account_document or {}, label="account team", field="team_id"
                )
                expected_team = self._expected_team_id(mode)
                if fresh_team != lease.team_id or fresh_team != expected_team:
                    raise RuntimeError("browser gateway CTFd team changed since preflight")
            result = execute_ctfd_browser_scoring(
                owned.page,
                CTFdScoringAction(
                    binding=binding,
                    challenge_id=challenge_id,
                    candidate=candidate,
                    csrf_token=lease.csrf_token,
                    timeout_seconds=self._timeout(),
                    max_response_bytes=self._browser_response_limit(),
                ),
                close_owned_target=owned.close,
            )
        finally:
            owned.dispose()
        response_path = evidence_root / "response.json"
        atomic_write_json(response_path, result.response, mode=0o600)
        gateway_after = self._gateway_counters(gateway_url, gateway)
        try:
            self._require_gateway_transfer(gateway_before, gateway_after)
        except RuntimeError as exc:
            raise BrowserCdpScoringError(str(exc), committed=True) from exc
        return {
            "response": result.response,
            "response_path": str(response_path),
            "verdict": result.verdict,
        }

    def execute_action(self, envelope: dict[str, Any], evidence_root: Path) -> dict[str, Any]:
        lease = self._current_lease()
        if scope_sha256(self.scope) != lease.scope_sha256:
            raise RuntimeError("browser gateway session binding changed since preflight")
        try:
            challenge_id = int(envelope.get("objective_id"))
        except (TypeError, ValueError) as exc:
            raise RuntimeError("browser gateway CTFd challenge id is invalid") from exc
        candidate = envelope.get("exact_value")
        if not isinstance(candidate, str):
            raise RuntimeError("browser gateway candidate is invalid")
        if envelope.get("action_kind") != "flag":
            raise RuntimeError("browser gateway action kind is invalid")
        ensure_private_dir(evidence_root)
        request_path = evidence_root / "request.json"
        request_evidence = {
            "adapter_id": self.id,
            "objective_id": str(envelope.get("objective_id") or ""),
            "candidate": candidate,
            "action_kind": envelope.get("action_kind"),
            "transport": lease.transport,
        }
        if lease.transport == "token":
            request_evidence["request"] = {
                "method": "POST",
                "path": "/api/v1/challenges/attempt",
            }
        if lease.transport == "browser_gateway":
            request_evidence["gateway_policy_sha256"] = lease.gateway_policy_sha256
        atomic_write_json(
            request_path,
            request_evidence,
            mode=0o600,
        )
        if lease.transport == "token":
            return self._token_submission(lease, challenge_id, candidate, evidence_root)
        if lease.transport == "browser_gateway":
            cdp_url, gateway_url, environment_origin = self._endpoints()
            verify_browser_cdp_endpoint(cdp_url)
            origin, gateway = self._gateway_identity(
                gateway_url,
                environment_origin,
                boot_nonce=lease.gateway_boot_nonce,
            )
            if (
                origin != lease.origin
                or gateway.policy_sha256 != lease.gateway_policy_sha256
                or gateway.expires_at != lease.gateway_expires_at
            ):
                raise RuntimeError("browser gateway session binding changed since preflight")
            return self._browser_submission(
                lease,
                cdp_url,
                gateway_url,
                origin,
                gateway,
                challenge_id,
                candidate,
                evidence_root,
            )
        raise RuntimeError("browser gateway transport lease is invalid")
