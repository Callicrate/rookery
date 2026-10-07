from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rookery.portable.adapters import (
    DEFAULT_ADAPTER_OUTPUT_BYTES,
    MAX_ADAPTER_OUTPUT_BYTES,
    Adapter,
    CapabilityHealth,
    bounded_response_bytes,
    normalized_snapshot,
)
from rookery.portable import browser_cdp as _browser_cdp
from rookery.portable.browser_bidi import BrowserBidiError, FirefoxBidiSession, verify_browser_bidi_endpoint
from rookery.portable.browser_cdp import BrowserCdpError, BrowserSession, read_browser_session
from rookery.portable.environment import (
    EnvClass,
    EnvKey,
    EnvSource,
    EnvironmentPolicyError,
    verify_browser_cdp_endpoint,
)
from rookery.portable.network_policy import ExplicitNetworkPolicy
from rookery.portable.scope import canonical_hostname, check_url, open_scoped_url
from rookery.portable.util import atomic_write_json, iso_now
from rookery.verdict_parser import parse_verdict

_SAFE_RESPONSE_HEADERS = frozenset(
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
_SENSITIVE_RESPONSE_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "proxy-authorization",
        "set-cookie",
        "www-authenticate",
    }
)
_MAX_SAVED_HEADER_BYTES = 512
_CSRF_PAGE_DEFAULT = "/challenges"
_CSRF_RESPONSE_MAX_BYTES = 1024 * 1024
_CSRF_NONCE_PATTERN = re.compile(r"[\"']?(?:csrf_nonce|csrfNonce)[\"']?\s*(?:=|:)\s*[\"']([A-Za-z0-9_.-]{16,256})[\"']")


class _TokenReadFallback(RuntimeError):
    """A read-only token authentication failure eligible for cookie fallback."""


@dataclass(frozen=True)
class _SessionLease:
    """The one browser-derived session preflight may hand to one submission."""

    transport: str
    base_url: str
    account_id: str
    team_id: str | None
    expires_at: float = field(repr=False)
    browser: BrowserSession | None = field(default=None, repr=False)
    browser_mode: str = ""
    browser_endpoint: str = field(default="", repr=False)
    csrf_token: str = field(default="", repr=False)
    token_fingerprint: str | None = field(default=None, repr=False)
    selected_challenge_id: str | None = field(default=None, repr=False)
    sequential_unlock: bool = field(default=False, repr=False)


def _response_header(headers: Any, name: str) -> str:
    if not headers:
        return ""
    try:
        value = headers.get(name)
    except AttributeError:
        return ""
    return value.strip() if isinstance(value, str) else ""


def _response_status(response: Any) -> int:
    status = getattr(response, "status", None)
    if isinstance(status, int) and not isinstance(status, bool):
        return status
    try:
        status = response.getcode()
    except AttributeError as exc:
        raise RuntimeError("CTFd response has no HTTP status") from exc
    if not isinstance(status, int) or isinstance(status, bool):
        raise RuntimeError("CTFd response has no HTTP status")
    return status


def _http_failure_detail(status: int, headers: Any) -> str:
    if _response_header(headers, "CF-Mitigated").casefold() == "challenge":
        return f"HTTP {status} Cloudflare challenge"
    return f"HTTP {status}"


def _privacy_safe_response_headers(headers: Any) -> dict[str, str]:
    if not headers:
        return {}
    try:
        items = headers.items()
    except AttributeError:
        return {}
    safe: dict[str, str] = {}
    for raw_name, raw_value in items:
        name = str(raw_name).strip().casefold()
        if name in _SENSITIVE_RESPONSE_HEADERS:
            safe[name] = "[redacted]"
        elif name in _SAFE_RESPONSE_HEADERS:
            value = str(raw_value).replace("\r", " ").replace("\n", " ").strip()
            encoded = value.encode("utf-8", errors="replace")
            if len(encoded) > _MAX_SAVED_HEADER_BYTES:
                value = encoded[:_MAX_SAVED_HEADER_BYTES].decode("utf-8", errors="ignore")
            safe[name] = value
    return dict(sorted(safe.items()))


def _json_document(response: Any, maximum: int, *, endpoint: str) -> dict[str, Any]:
    status = _response_status(response)
    if not 200 <= status < 300:
        raise RuntimeError(_http_failure_detail(status, getattr(response, "headers", None)))
    content_type = _response_header(getattr(response, "headers", None), "Content-Type")
    if content_type.split(";", 1)[0].strip().casefold() != "application/json":
        raise RuntimeError(f"HTTP {status} expected application/json")
    raw = bounded_response_bytes(response, maximum)
    if not raw:
        raise RuntimeError(f"HTTP {status} empty response")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"HTTP {status} invalid JSON response") from exc
    if not isinstance(document, dict) or document.get("success") is not True:
        raise RuntimeError(f"HTTP {status} invalid CTFd {endpoint} response")
    return document


def _ctfd_challenges(response: Any, maximum: int) -> list[dict[str, Any]]:
    document = _json_document(response, maximum, endpoint="inventory")
    challenges = document.get("data")
    if not isinstance(challenges, list) or not all(isinstance(challenge, dict) for challenge in challenges):
        raise RuntimeError("HTTP 200 invalid CTFd inventory response")
    return challenges


def _ctfd_account_id(response: Any, maximum: int) -> str:
    document = _json_document(response, maximum, endpoint="session")
    data = document.get("data")
    identifier = data.get("id") if isinstance(data, dict) else None
    if isinstance(identifier, bool) or not isinstance(identifier, (int, str)):
        raise RuntimeError("HTTP 200 invalid CTFd session response")
    account_id = str(identifier)
    if not account_id or len(account_id.encode("utf-8")) > 256:
        raise RuntimeError("HTTP 200 invalid CTFd session response")
    return account_id


def _ctfd_team_id(response: Any, maximum: int) -> str:
    document = _json_document(response, maximum, endpoint="team session")
    data = document.get("data")
    identifier = data.get("id") if isinstance(data, dict) else None
    if isinstance(identifier, bool) or not isinstance(identifier, (int, str)):
        raise RuntimeError("HTTP 200 invalid CTFd team session response")
    team_id = str(identifier)
    if not team_id or len(team_id.encode("utf-8")) > 256:
        raise RuntimeError("HTTP 200 invalid CTFd team session response")
    return team_id


def _ctfd_csrf_nonce(response: Any, maximum: int) -> str:
    """Extract the one CTFd page nonce required for JSON mutation requests."""

    status = _response_status(response)
    if not 200 <= status < 300:
        raise RuntimeError(_http_failure_detail(status, getattr(response, "headers", None)))
    content_type = _response_header(getattr(response, "headers", None), "Content-Type")
    if content_type.split(";", 1)[0].strip().casefold() != "text/html":
        raise RuntimeError(f"HTTP {status} expected text/html for CTFd CSRF nonce")
    raw = bounded_response_bytes(response, min(maximum, _CSRF_RESPONSE_MAX_BYTES))
    try:
        document = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"HTTP {status} invalid CTFd CSRF page") from exc
    matches = set(_CSRF_NONCE_PATTERN.findall(document))
    if len(matches) != 1:
        raise RuntimeError(f"HTTP {status} CTFd CSRF nonce is missing or ambiguous")
    return next(iter(matches))


def _browser_capabilities(mode: str, *, healthy: bool, detail: str = "") -> list[CapabilityHealth]:
    status = "healthy" if healthy else "unhealthy"
    freshness = iso_now() if healthy else "stale"
    specific = "browser_bidi" if mode == "bidi" else "browser_cdp"
    return [
        CapabilityHealth(name, "available", status, freshness, "read-only", (), detail)
        for name in ("browser_remote", specific)
    ]


def _read_bidi_browser_session(
    endpoint: str,
    base_url: str,
    *,
    target_id: str | None,
) -> BrowserSession:
    """Read one CTFd session through shared Firefox BiDi read primitives."""

    origin = _browser_cdp._configured_origin(base_url)
    if target_id is not None and (
        not isinstance(target_id, str)
        or not target_id
        or len(target_id.encode("utf-8")) > _browser_cdp.CDP_MAX_TARGET_ID_BYTES
        or _browser_cdp._has_control(target_id)
    ):
        raise BrowserBidiError("browser_bidi_context_invalid")
    with FirefoxBidiSession(endpoint) as browser:
        matches = [
            context
            for context in browser.contexts()
            if context.get("parent") is None
            and _browser_cdp._target_matches_origin(context.get("url"), origin)
            and (target_id is None or context.get("context") == target_id)
        ]
        if not matches:
            raise BrowserBidiError("browser_bidi_context_missing")
        if len(matches) != 1:
            raise BrowserBidiError("browser_bidi_context_ambiguous")
        context_id = matches[0].get("context")
        if (
            not isinstance(context_id, str)
            or not context_id
            or len(context_id.encode("utf-8")) > _browser_cdp.CDP_MAX_TARGET_ID_BYTES
            or _browser_cdp._has_control(context_id)
        ):
            raise BrowserBidiError("browser_bidi_context_invalid")
        try:
            user_agent = _browser_cdp._valid_user_agent(browser.user_agent(context_id))
        except BrowserCdpError as exc:
            raise BrowserBidiError("browser_bidi_user_agent_invalid") from exc
        result = browser.cookies(context_id)
    partition = result["partitionKey"]
    if "sourceOrigin" in partition and not _browser_cdp._target_matches_origin(
        partition["sourceOrigin"], origin
    ):
        raise BrowserBidiError("browser_bidi_partition_invalid")
    selected: list[dict[str, Any]] = []
    for cookie in result["cookies"]:
        domain = cookie.get("domain")
        if not isinstance(domain, str):
            raise BrowserBidiError("browser_bidi_cookie_invalid")
        try:
            canonical_domain = canonical_hostname(domain.lstrip("."))
        except (UnicodeError, ValueError) as exc:
            raise BrowserBidiError("browser_bidi_cookie_invalid") from exc
        if not canonical_domain:
            raise BrowserBidiError("browser_bidi_cookie_invalid")
        if origin.host != canonical_domain and not origin.host.endswith("." + canonical_domain):
            continue
        path = cookie.get("path")
        if not isinstance(path, str) or not path.startswith("/"):
            raise BrowserBidiError("browser_bidi_cookie_invalid")
        if not any(
            _browser_cdp._cookie_path_matches(path, request_path)
            for request_path in _browser_cdp._CTFD_SESSION_PATHS
        ):
            continue
        raw_value = cookie.get("value")
        if not isinstance(raw_value, dict) or set(raw_value) != {"type", "value"}:
            raise BrowserBidiError("browser_bidi_cookie_invalid")
        value = raw_value.get("value")
        if not isinstance(value, str):
            raise BrowserBidiError("browser_bidi_cookie_invalid")
        if raw_value.get("type") == "base64":
            try:
                value = base64.b64decode(value, validate=True).decode("latin-1")
            except (binascii.Error, ValueError, UnicodeError) as exc:
                raise BrowserBidiError("browser_bidi_cookie_invalid") from exc
        elif raw_value.get("type") != "string":
            raise BrowserBidiError("browser_bidi_cookie_invalid")
        selected.append(
            {
                "name": cookie.get("name"),
                "value": value,
                "domain": domain,
                "path": path,
                "secure": cookie.get("secure"),
                "expires": cookie.get("expiry", -1),
            }
        )
    try:
        cookie_header = _browser_cdp._cookie_header(selected, origin)
    except BrowserCdpError as exc:
        raise BrowserBidiError("browser_bidi_cookie_invalid") from exc
    return BrowserSession(
        origin=origin.value,
        target_id=context_id,
        cookie_header=cookie_header,
        user_agent=user_agent,
    )


def _unhealthy_capabilities(
    detail: str,
    *,
    browser_checks: list[CapabilityHealth],
) -> list[CapabilityHealth]:
    return [
        *browser_checks,
        CapabilityHealth(
            "platform_inventory",
            "available",
            "unhealthy",
            "stale",
            "read-only",
            (),
            detail,
        ),
        CapabilityHealth(
            "challenge_details",
            "available",
            "unhealthy",
            "stale",
            "read-only",
            (),
            detail,
        ),
        CapabilityHealth(
            "scoring",
            "available",
            "unhealthy",
            "stale",
            "reviewer-only",
            ("flag", "free_text"),
            detail,
        ),
    ]


class CTFdBrowserAdapter(Adapter):
    """CTFd integration that reads Chrome cookies but never asks Chrome to act."""

    id = "ctfd_browser"

    def __init__(self, root: Path, manifest: dict[str, Any], scope: dict[str, Any]):
        super().__init__(root, manifest, scope)
        self._lease: _SessionLease | None = None

    def _positive_int(self, name: str, default: int, maximum: int) -> int:
        value = self.config.get(name, default)
        if isinstance(value, bool):
            raise RuntimeError(f"CTFd browser {name} must be an integer")
        try:
            resolved = int(value)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"CTFd browser {name} must be an integer") from exc
        if not 1 <= resolved <= maximum:
            raise RuntimeError(f"CTFd browser {name} is outside supported range")
        return resolved

    def _response_limit(self) -> int:
        return self._positive_int("max_response_bytes", DEFAULT_ADAPTER_OUTPUT_BYTES, MAX_ADAPTER_OUTPUT_BYTES)

    def _base_and_browser_endpoint(self) -> tuple[str, str, str]:
        resolved = self._resolve_local_environment(
            (
                EnvKey(
                    "CTFD_URL",
                    EnvClass.ROOKERY_CONFIG,
                    sources=(EnvSource.DOTENV, EnvSource.PARENT),
                ),
                EnvKey(
                    "BROWSER_MODE",
                    EnvClass.ROOKERY_CONFIG,
                    sources=(EnvSource.DOTENV, EnvSource.PARENT),
                ),
                EnvKey(
                    "BROWSER_CDP_URL",
                    EnvClass.ROOKERY_CONFIG,
                    sources=(EnvSource.DOTENV, EnvSource.PARENT),
                ),
                EnvKey(
                    "BROWSER_BIDI_URL",
                    EnvClass.ROOKERY_CONFIG,
                    sources=(EnvSource.DOTENV, EnvSource.PARENT),
                ),
            )
        )
        configured = self.config.get("base_url")
        if configured is not None and not isinstance(configured, str):
            raise RuntimeError("CTFd browser base_url must be a string")
        base = (
            configured.strip()
            if isinstance(configured, str) and configured.strip() not in {"", "unknown"}
            else str(resolved.get("CTFD_URL") or "").strip()
        ).rstrip("/")
        if not base or base == "unknown":
            raise RuntimeError("CTFd base URL unresolved")
        mode = str(resolved.get("BROWSER_MODE") or "cdp").strip().casefold()
        if mode not in {"cdp", "bidi"}:
            raise RuntimeError("browser CTFd mode is invalid")
        endpoint_name = "BROWSER_BIDI_URL" if mode == "bidi" else "BROWSER_CDP_URL"
        endpoint = str(resolved.get(endpoint_name) or "").strip()
        if not endpoint:
            raise RuntimeError(f"browser CTFd {endpoint_name} is required")
        return base, mode, endpoint

    def _target_id(self) -> str | None:
        value = self.config.get("target_id")
        if value is None or (isinstance(value, str) and value in {"", "unknown"}):
            return None
        if not isinstance(value, str):
            raise RuntimeError("CTFd browser target_id must be a string")
        return value

    @staticmethod
    def _required_identifier(value: object, *, label: str) -> str:
        if value is None or (isinstance(value, str) and value in {"", "unknown"}):
            raise RuntimeError(f"CTFd browser {label} is required")
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise RuntimeError(f"CTFd browser {label} is invalid")
        expected = str(value)
        if not expected or len(expected.encode("utf-8")) > 256:
            raise RuntimeError(f"CTFd browser {label} is invalid")
        return expected

    def _scoring_mode(self) -> str:
        value = self.config.get("scoring_mode")
        if not isinstance(value, str) or value not in {"user", "team"}:
            raise RuntimeError("CTFd browser scoring_mode must be user or team")
        return value

    def _expected_account_id(self) -> str:
        value = self.config.get("expected_account_id")
        return self._required_identifier(value, label="expected_account_id")

    def _expected_team_id(self, mode: str) -> str | None:
        configured = self.config.get("expected_team_id")
        if mode == "user":
            if configured is not None and not (isinstance(configured, str) and configured in {"", "unknown"}):
                raise RuntimeError("CTFd browser expected_team_id requires scoring_mode team")
            return None
        return self._required_identifier(
            configured,
            label="expected_team_id",
        )

    def _csrf_page_path(self) -> str:
        value = self.config.get("csrf_page_path", _CSRF_PAGE_DEFAULT)
        if not isinstance(value, str) or not re.fullmatch(r"/[A-Za-z0-9/_-]{0,255}", value):
            raise RuntimeError("CTFd browser csrf_page_path is invalid")
        return value

    def _sequential_unlock_enabled(self) -> bool:
        """Return the explicit selected-adapter sequential inventory mode."""

        value = self.config.get("sequential_unlock", False)
        if isinstance(value, bool):
            return value
        raise RuntimeError("CTFd browser sequential_unlock must be a boolean")

    @staticmethod
    def _challenge_identifier(challenge: dict[str, Any]) -> str:
        identifier = challenge.get("id")
        if isinstance(identifier, bool) or not isinstance(identifier, (int, str)):
            raise RuntimeError("CTFd browser sequential inventory challenge id is invalid")
        value = str(identifier)
        if not value or len(value.encode("utf-8")) > 256:
            raise RuntimeError("CTFd browser sequential inventory challenge id is invalid")
        return value

    def _next_sequential_challenge(self, challenges: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str | None]:
        """Expose the next unsolved accessible position, excluding locked previews."""

        if not self._sequential_unlock_enabled():
            return challenges, None
        indexed: list[tuple[int, str, dict[str, Any], bool]] = []
        positions: set[int] = set()
        for challenge in challenges:
            solved = challenge.get("solved_by_me")
            if challenge.get("type") == "hidden":
                # CTFd uses this exact shape for unmet prerequisite previews.
                if (
                    solved is not False
                    or "position" in challenge
                    or "module_id" in challenge
                    or challenge.get("template") != ""
                    or challenge.get("script") != ""
                ):
                    raise RuntimeError("CTFd browser sequential inventory hidden preview is invalid")
                self._challenge_identifier(challenge)
                continue
            position = challenge.get("position")
            if (
                isinstance(position, bool)
                or not isinstance(position, int)
                or position < 0
                or not isinstance(solved, bool)
            ):
                raise RuntimeError("CTFd browser sequential inventory is invalid")
            if position in positions:
                raise RuntimeError("CTFd browser sequential inventory position is duplicate")
            positions.add(position)
            indexed.append((position, self._challenge_identifier(challenge), challenge, solved))
        pending = [item for item in indexed if item[3] is False]
        if not pending:
            return [], None
        _position, identifier, challenge, _solved = min(
            pending,
            key=lambda item: (item[0], item[1]),
        )
        return [challenge], identifier

    def _transport(self) -> Any:
        return ExplicitNetworkPolicy.from_child_environment(self._empty_environment()).scoped_transport(
            self.scope, platform=True
        )

    def _token(self) -> str | None:
        """Read only the selected adapter's optional CTFd token value."""

        resolved = self._resolve_local_environment(
            (
                EnvKey(
                    "CTFD_TOKEN",
                    EnvClass.ADAPTER_SECRET,
                    sources=(EnvSource.DOTENV, EnvSource.PARENT),
                ),
            )
        )
        value = str(resolved.get("CTFD_TOKEN") or "")
        if not value:
            return None
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
            raise RuntimeError("CTFd browser token is invalid")
        return value

    @staticmethod
    def _response_url(response: Any, requested_url: str) -> str:
        try:
            value = response.geturl()
        except AttributeError:
            return requested_url
        if not isinstance(value, str):
            raise RuntimeError("CTFd browser token response URL is invalid")
        return value

    @staticmethod
    def _origin(url: str) -> tuple[str, str, int]:
        try:
            parsed = urllib.parse.urlsplit(url)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError
            return parsed.scheme, parsed.hostname.casefold(), parsed.port or 443
        except ValueError as exc:
            raise RuntimeError("CTFd browser token response URL is invalid") from exc

    def _token_request(
        self,
        base: str,
        token: str,
        path: str,
        *,
        transport: Any,
    ) -> dict[str, Any]:
        """Issue one fixed token GET, classifying only clear auth fallback."""

        url = base + path
        decision = check_url(self.scope, url, platform=True)
        if not decision.allowed:
            raise RuntimeError(decision.reason)
        request = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "Authorization": f"Token {token}"},
            method="GET",
        )
        try:
            with open_scoped_url(
                self.scope,
                request,
                timeout=self._positive_int("timeout", 30, 120),
                platform=True,
                max_redirects=1,
                transport=transport,
            ) as response:
                status = _response_status(response)
                response_url = self._response_url(response, request.full_url)
                if self._origin(response_url) != self._origin(request.full_url):
                    raise RuntimeError("CTFd browser token redirect origin is invalid")
                if response_url != request.full_url:
                    parsed = urllib.parse.urlsplit(response_url)
                    if parsed.path == "/login":
                        raise _TokenReadFallback("ctfd_token_login_redirect")
                    raise RuntimeError("CTFd browser token redirect is invalid")
                if status in {401, 403}:
                    raise _TokenReadFallback(f"ctfd_token_http_{status}")
                if not 200 <= status < 300:
                    raise RuntimeError(f"CTFd browser token HTTP {status}")
                content_type = _response_header(response.headers, "Content-Type")
                if content_type.split(";", 1)[0].strip().casefold() == "text/html":
                    bounded_response_bytes(response, self._response_limit())
                    raise _TokenReadFallback("ctfd_token_html_access")
                return _json_document(response, self._response_limit(), endpoint="token")
        except _TokenReadFallback:
            raise
        except urllib.error.HTTPError as exc:
            if exc.code in {401, 403}:
                raise _TokenReadFallback(f"ctfd_token_http_{exc.code}") from exc
            raise RuntimeError(f"CTFd browser token HTTP {exc.code}") from exc

    @staticmethod
    def _empty_environment():
        from rookery.portable.environment import ChildEnvironment

        return ChildEnvironment({}, "ctfd-browser-network", ())

    def _request(
        self,
        base: str,
        path: str,
        browser: BrowserSession,
        *,
        transport: Any,
        method: str = "GET",
        body: bytes | None = None,
        accept: str = "application/json",
        csrf_token: str | None = None,
    ) -> Any:
        url = base + path
        decision = check_url(self.scope, url, platform=True)
        if not decision.allowed:
            raise RuntimeError(decision.reason)
        headers = {
            "Accept": accept,
            "Cookie": browser.cookie_header,
            "Origin": browser.origin,
            "User-Agent": browser.user_agent,
        }
        if csrf_token is not None:
            headers["CSRF-Token"] = csrf_token
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body, method=method, headers=headers)
        return open_scoped_url(
            self.scope,
            request,
            timeout=self._positive_int("timeout", 30, 120),
            platform=True,
            max_redirects=0,
            transport=transport,
        )

    def _new_cookie_lease(
        self,
        *,
        mode: str,
        expected_account: str,
        expected_team: str | None,
        base: str,
        browser_mode: str,
        browser_endpoint: str,
    ) -> tuple[_SessionLease, list[dict[str, Any]]]:
        """Establish the existing cookie-relay lease after token auth fails."""

        if browser_mode == "bidi":
            browser = _read_bidi_browser_session(
                browser_endpoint, base, target_id=self._target_id()
            )
        else:
            browser = read_browser_session(
                browser_endpoint, base, target_id=self._target_id()
            )
        transport = self._transport()
        with self._request(
            base,
            "/api/v1/users/me",
            browser,
            transport=transport,
        ) as response:
            account_id = _ctfd_account_id(response, self._response_limit())
        if account_id != expected_account:
            raise RuntimeError("browser CTFd account does not match expected account")
        with self._request(
            base,
            self._csrf_page_path(),
            browser,
            transport=transport,
            accept="text/html",
        ) as response:
            csrf_token = _ctfd_csrf_nonce(response, self._response_limit())
        team_id: str | None = None
        if mode == "team":
            with self._request(
                base,
                "/api/v1/teams/me",
                browser,
                transport=transport,
            ) as response:
                team_id = _ctfd_team_id(response, self._response_limit())
            if team_id != expected_team:
                raise RuntimeError("browser CTFd team does not match expected team")
        with self._request(
            base,
            "/api/v1/challenges",
            browser,
            transport=transport,
        ) as response:
            challenges = _ctfd_challenges(response, self._response_limit())
        visible_challenges, selected_challenge_id = self._next_sequential_challenge(challenges)
        lease = _SessionLease(
            transport="browser",
            browser=browser,
            browser_mode=browser_mode,
            browser_endpoint=browser_endpoint,
            base_url=base,
            account_id=account_id,
            team_id=team_id,
            csrf_token=csrf_token,
            expires_at=time.monotonic() + self._positive_int("session_lease_seconds", 60, 300),
            selected_challenge_id=selected_challenge_id,
            sequential_unlock=self._sequential_unlock_enabled(),
        )
        return lease, visible_challenges

    def _token_identifier(self, document: dict[str, Any], *, label: str) -> str:
        data = document.get("data")
        identifier = data.get("id") if isinstance(data, dict) else None
        return self._required_identifier(identifier, label=f"token_{label}_id")

    def _new_token_lease(
        self,
        *,
        mode: str,
        expected_account: str,
        expected_team: str | None,
        base: str,
        token: str,
    ) -> tuple[_SessionLease, list[dict[str, Any]]]:
        """Prove a fixed bearer-token identity and inventory before scoring."""

        transport = self._transport()
        account = self._token_request(
            base,
            token,
            "/api/v1/users/me",
            transport=transport,
        )
        account_id = self._token_identifier(account, label="account")
        if account_id != expected_account:
            raise RuntimeError("token CTFd account does not match expected account")
        team_id: str | None = None
        if mode == "team":
            team = self._token_request(
                base,
                token,
                "/api/v1/teams/me",
                transport=transport,
            )
            team_id = self._token_identifier(team, label="team")
            if team_id != expected_team:
                raise RuntimeError("token CTFd team does not match expected team")
        inventory = self._token_request(
            base,
            token,
            "/api/v1/challenges",
            transport=transport,
        )
        challenges = inventory.get("data")
        if not isinstance(challenges, list) or not all(isinstance(item, dict) for item in challenges):
            raise RuntimeError("token CTFd inventory is invalid")
        visible_challenges, selected_challenge_id = self._next_sequential_challenge(challenges)
        lease = _SessionLease(
            transport="token",
            base_url=base,
            account_id=account_id,
            team_id=team_id,
            expires_at=time.monotonic() + self._positive_int("session_lease_seconds", 60, 300),
            selected_challenge_id=selected_challenge_id,
            sequential_unlock=self._sequential_unlock_enabled(),
            token_fingerprint=hashlib.sha256(token.encode("utf-8")).hexdigest(),
        )
        return lease, visible_challenges

    def _configured_runtime(self) -> tuple[str, str, str | None, str, str, str]:
        mode = self._scoring_mode()
        expected_account = self._expected_account_id()
        expected_team = self._expected_team_id(mode)
        base, browser_mode, browser_endpoint = self._base_and_browser_endpoint()
        if not check_url(self.scope, base, platform=True).allowed:
            raise RuntimeError("CTFd base URL is outside declared platform scope")
        return mode, expected_account, expected_team, base, browser_mode, browser_endpoint

    def _new_lease(
        self,
        *,
        mode: str,
        expected_account: str,
        expected_team: str | None,
        base: str,
        browser_mode: str,
        browser_endpoint: str,
    ) -> tuple[_SessionLease, list[dict[str, Any]]]:
        token = self._token()
        if token is not None:
            try:
                return self._new_token_lease(
                    mode=mode,
                    expected_account=expected_account,
                    expected_team=expected_team,
                    base=base,
                    token=token,
                )
            except _TokenReadFallback:
                pass
        return self._new_cookie_lease(
            mode=mode,
            expected_account=expected_account,
            expected_team=expected_team,
            base=base,
            browser_mode=browser_mode,
            browser_endpoint=browser_endpoint,
        )

    def sync(self) -> dict[str, Any]:
        self._lease = None
        browser_mode = "cdp"
        try:
            mode, expected_account, expected_team, base, browser_mode, browser_endpoint = self._configured_runtime()
        except (BrowserBidiError, BrowserCdpError, OSError, RuntimeError, TypeError, ValueError) as exc:
            detail = str(exc)
            return normalized_snapshot(
                self.id,
                _unhealthy_capabilities(
                    detail,
                    browser_checks=_browser_capabilities(
                        browser_mode,
                        healthy=False,
                        detail=f"browser_{browser_mode}_not_checked: {detail}",
                    ),
                ),
                [],
            )
        try:
            if browser_mode == "bidi":
                verify_browser_bidi_endpoint(browser_endpoint)
            else:
                verify_browser_cdp_endpoint(browser_endpoint)
        except (EnvironmentPolicyError, OSError, RuntimeError, TypeError, ValueError) as exc:
            detail = str(exc)
            return normalized_snapshot(
                self.id,
                _unhealthy_capabilities(
                    detail,
                    browser_checks=_browser_capabilities(
                        browser_mode,
                        healthy=False,
                        detail=detail,
                    ),
                ),
                [],
            )
        browser_checks = _browser_capabilities(browser_mode, healthy=True)
        try:
            lease, challenges = self._new_lease(
                mode=mode,
                expected_account=expected_account,
                expected_team=expected_team,
                base=base,
                browser_mode=browser_mode,
                browser_endpoint=browser_endpoint,
            )
        except (BrowserBidiError, BrowserCdpError) as exc:
            detail = str(exc)
            return normalized_snapshot(
                self.id,
                _unhealthy_capabilities(
                    detail,
                    browser_checks=_browser_capabilities(
                        browser_mode,
                        healthy=False,
                        detail=detail,
                    ),
                ),
                [],
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            return normalized_snapshot(
                self.id,
                _unhealthy_capabilities(str(exc), browser_checks=browser_checks),
                [],
            )
        self._lease = lease
        caps = [
            *browser_checks,
            CapabilityHealth("platform_inventory", "available", "healthy", iso_now(), "read-only", ()),
            CapabilityHealth("challenge_details", "available", "healthy", iso_now(), "read-only", ()),
            CapabilityHealth("release_changes", "available", "healthy", iso_now(), "read-only", ()),
            CapabilityHealth(
                "scoring",
                "available",
                "healthy",
                iso_now(),
                "reviewer-only",
                ("flag", "free_text"),
            ),
        ]
        return normalized_snapshot(self.id, caps, challenges)

    def _current_lease(self) -> _SessionLease:
        lease = self._lease
        if lease is None or time.monotonic() >= lease.expires_at:
            self._lease = None
            raise RuntimeError("browser session lease is unavailable or expired")
        return lease

    def _execute_token_action(
        self,
        lease: _SessionLease,
        *,
        challenge_id: int,
        candidate: object,
        evidence_root: Path,
    ) -> dict[str, Any]:
        """Release one bearer-token POST with no cross-transport retry."""

        token = self._token()
        if (
            token is None
            or lease.token_fingerprint is None
            or not hmac.compare_digest(
                lease.token_fingerprint,
                hashlib.sha256(token.encode("utf-8")).hexdigest(),
            )
        ):
            raise RuntimeError("token CTFd lease binding changed since preflight")
        body = json.dumps(
            {"challenge_id": challenge_id, "submission": candidate},
            separators=(",", ":"),
        ).encode("utf-8")
        request = urllib.request.Request(
            lease.base_url + "/api/v1/challenges/attempt",
            data=body,
            method="POST",
            headers={
                "Accept": "application/json",
                "Authorization": f"Token {token}",
                "Content-Type": "application/json",
            },
        )
        transport = self._transport()
        try:
            transport.preflight_url(request.full_url)
        except Exception as exc:
            raise RuntimeError("token CTFd post transport is not admitted") from exc
        atomic_write_json(
            evidence_root / "request.json",
            {
                "url": request.full_url,
                "body": json.loads(body),
                "objective_id": str(challenge_id),
                "candidate": candidate,
                "session_source": "ctfd_token_memory_lease",
            },
            mode=0o600,
        )
        response_path = evidence_root / "response.json"
        try:
            with open_scoped_url(
                self.scope,
                request,
                timeout=self._positive_int("timeout", 30, 120),
                platform=True,
                max_redirects=0,
                transport=transport,
            ) as response:
                status = _response_status(response)
                headers = _privacy_safe_response_headers(response.headers)
                raw = bounded_response_bytes(response, self._response_limit())
        except urllib.error.HTTPError as exc:
            status = exc.code
            headers = _privacy_safe_response_headers(exc.headers)
            raw = bounded_response_bytes(exc, self._response_limit())
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
                    {"transport": "token", "http_status": status, "phase": "ctfd_token_post_invalid"},
                    mode=0o600,
                )
                raise RuntimeError("ctfd_token_post_invalid")
            try:
                document = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                atomic_write_json(
                    response_path,
                    {"transport": "token", "http_status": status, "phase": "ctfd_token_post_invalid"},
                    mode=0o600,
                )
                raise RuntimeError("ctfd_token_post_invalid") from exc
            if not isinstance(document, dict) or not isinstance(document.get("success"), bool):
                atomic_write_json(
                    response_path,
                    {"transport": "token", "http_status": status, "phase": "ctfd_token_post_invalid"},
                    mode=0o600,
                )
                raise RuntimeError("ctfd_token_post_invalid")
        else:
            try:
                document = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                document = {"message": f"token CTFd HTTP {status}"}
        response_obj = {"http_status": status, "headers": headers, "data": document}
        atomic_write_json(response_path, response_obj, mode=0o600)
        verdict = parse_verdict(response_obj, http_status=status)
        return {
            "response": response_obj,
            "response_path": str(response_path),
            "verdict": verdict.to_dict(),
        }

    def execute_action(self, envelope: dict[str, Any], evidence_root: Path) -> dict[str, Any]:
        lease = self._current_lease()
        self._lease = None
        current_base, current_mode, current_endpoint = self._base_and_browser_endpoint()
        if current_base != lease.base_url:
            raise RuntimeError("browser CTFd base URL changed since preflight")
        if lease.transport == "browser" and (
            current_mode != lease.browser_mode or current_endpoint != lease.browser_endpoint
        ):
            raise RuntimeError("browser CTFd endpoint changed since preflight")
        if self._sequential_unlock_enabled() != lease.sequential_unlock:
            raise RuntimeError("browser CTFd sequential mode changed since preflight")
        objective_id = envelope.get("objective_id")
        if isinstance(objective_id, bool) or not isinstance(objective_id, (int, str)):
            raise RuntimeError("browser CTFd challenge id is invalid")
        if lease.sequential_unlock:
            if lease.selected_challenge_id is None:
                raise RuntimeError("browser CTFd sequential inventory has no unsolved challenge")
            if str(objective_id) != lease.selected_challenge_id:
                raise RuntimeError("browser CTFd sequential challenge changed since preflight")
        try:
            challenge_id = int(objective_id)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("browser CTFd challenge id is invalid") from exc
        if challenge_id < 0:
            raise RuntimeError("browser CTFd challenge id is invalid")
        base = lease.base_url
        body = json.dumps(
            {
                "challenge_id": challenge_id,
                "submission": envelope.get("exact_value", ""),
            }
        ).encode("utf-8")
        evidence_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            os.chmod(evidence_root, 0o700)
        if lease.transport == "token":
            return self._execute_token_action(
                lease,
                challenge_id=challenge_id,
                candidate=envelope.get("exact_value", ""),
                evidence_root=evidence_root,
            )
        if lease.browser is None:
            raise RuntimeError("browser CTFd lease transport is invalid")
        atomic_write_json(
            evidence_root / "request.json",
            {
                "url": base + "/api/v1/challenges/attempt",
                "body": json.loads(body),
                "objective_id": envelope["objective_id"],
                "candidate": envelope.get("exact_value", ""),
                "session_source": "ctfd_browser_memory_lease",
            },
            mode=0o600,
        )
        try:
            with self._request(
                base,
                "/api/v1/challenges/attempt",
                lease.browser,
                transport=self._transport(),
                method="POST",
                body=body,
                csrf_token=lease.csrf_token,
            ) as response:
                status = _response_status(response)
                raw_headers = response.headers
                failure_detail = _http_failure_detail(status, raw_headers)
                headers = _privacy_safe_response_headers(raw_headers)
                raw = bounded_response_bytes(response, self._response_limit())
        except urllib.error.HTTPError as exc:
            status = exc.code
            failure_detail = _http_failure_detail(status, exc.headers)
            headers = _privacy_safe_response_headers(exc.headers)
            raw = bounded_response_bytes(exc, self._response_limit())
        if 200 <= status < 300:
            content_type = headers.get("content-type", "").split(";", 1)[0].casefold()
            if content_type != "application/json":
                raise RuntimeError(f"HTTP {status} expected application/json")
            try:
                document = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"HTTP {status} invalid JSON response") from exc
            if not isinstance(document, dict) or not isinstance(document.get("success"), bool):
                raise RuntimeError(f"HTTP {status} invalid CTFd scoring response")
        else:
            document = {"message": failure_detail}
        response_obj = {
            "http_status": status,
            "headers": headers,
            "data": document,
        }
        atomic_write_json(evidence_root / "response.json", response_obj, mode=0o600)
        verdict = parse_verdict(response_obj, http_status=status)
        return {
            "response": response_obj,
            "response_path": str(evidence_root / "response.json"),
            "verdict": verdict.to_dict(),
        }
