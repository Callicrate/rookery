"""Bounded CDP state machine for one reviewed CTFd scoring attempt.

This module deliberately does not open a CDP socket or expose arbitrary browser
commands. A future selected adapter may supply a channel only after it has
verified the sealed loopback gateway and prepared target binding.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol

from rookery.verdict_parser import Verdict, parse_verdict

from .scope import canonical_hostname, default_port_for_scheme

ATTEMPT_PATH = "/api/v1/challenges/attempt"
_READ_ONLY_PATHS = {
    "account": ("/api/v1/users/me", "application/json"),
    "inventory": ("/api/v1/challenges", "application/json"),
    "team": ("/api/v1/teams/me", "application/json"),
}
MAX_CDP_MESSAGES = 256
MAX_CANDIDATE_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_HEADER_COUNT = 128
MAX_HEADER_BYTES = 32 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_ITEMS = 8192
MAX_JSON_STRING_BYTES = 64 * 1024
_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,512}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_CSRF = re.compile(r"[A-Za-z0-9_.-]{16,256}")
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
_CTFD_ATTEMPT_STATUS_VALUES = frozenset(
    {"correct", "incorrect", "already_solved"}
)
_ALLOWED_METHODS = frozenset(
    {
        "Fetch.continueRequest",
        "Fetch.continueResponse",
        "Fetch.enable",
        "Fetch.failRequest",
        "Fetch.getResponseBody",
        "Network.setBypassServiceWorker",
        "Network.setCacheDisabled",
        "Network.disable",
        "Network.enable",
        "Page.createIsolatedWorld",
        "Page.disable",
        "Page.enable",
        "Page.getFrameTree",
        "Page.navigate",
        "Page.setDownloadBehavior",
        "Runtime.callFunctionOn",
        "Runtime.disable",
        "Runtime.enable",
        "Runtime.evaluate",
        "Target.getTargetInfo",
        "Target.getTargets",
        "Target.setAutoAttach",
    }
)
_UNSAFE_NETWORK_EVENTS = frozenset(
    {
        "Network.directTCPSocketCreated",
        "Network.webSocketCreated",
        "Network.webTransportCreated",
    }
)
_UNSAFE_TARGET_EVENTS = frozenset(
    {
        "Target.attachedToTarget",
        "Target.targetCreated",
        "Target.targetInfoChanged",
    }
)
_ACTIVE_TARGET_TYPES = frozenset({"page", "service_worker", "shared_worker", "worker"})
_FETCH_RESOURCE_TYPES = frozenset({"Fetch", "XHR"})
_SCORING_WORLD_NAME = "rookery-browser-scoring"
_FIXED_FETCH_FUNCTION = """async function(requestUrl, requestMethod, canonicalBody, csrfToken, accept, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const headers = {"Accept": accept};
    if (canonicalBody !== null) headers["Content-Type"] = "application/json";
    if (csrfToken !== "") headers["CSRF-Token"] = csrfToken;
    const options = {
      method: requestMethod,
      headers,
      credentials: "include",
      redirect: "manual",
      cache: "no-store",
      signal: controller.signal
    };
    if (canonicalBody !== null) options.body = canonicalBody;
    const response = await fetch(requestUrl, options);
    return {
      url: response.url,
      status: response.status,
      redirected: response.redirected,
      type: response.type,
      contentType: response.headers.get("content-type") || ""
    };
  } finally {
    clearTimeout(timer);
  }
}"""


class CdpChannel(Protocol):
    """Message-oriented CDP channel supplied by the future adapter boundary."""

    def send_command(self, method: str, params: dict[str, Any]) -> int:
        """Send one command and return its positive request identifier."""

    def receive_message(self, timeout_seconds: float) -> dict[str, Any]:
        """Return one decoded CDP response or event within the timeout."""


class OwnedTargetCloser(Protocol):
    """Browser-level closure for one adapter-created disposable target."""

    def __call__(self, target_id: str, timeout_seconds: float) -> bool:
        """Close the exact target and return only after Chrome confirms it."""


class BrowserCdpScoringError(RuntimeError):
    """Value-free terminal failure from the bounded scoring state machine."""

    def __init__(self, reason: str, *, committed: bool) -> None:
        super().__init__(reason)
        self.reason = reason
        self.committed = committed
        self.outcome = "indeterminate" if committed else "not_committed"


@dataclass(frozen=True)
class BrowserScoringBinding:
    """Exact prepared browser and sealed network-path identity."""

    origin: str
    page_url: str
    target_id: str
    browser_context_id: str | None
    frame_id: str
    execution_context_unique_id: str
    gateway_policy_sha256: str

    def __post_init__(self) -> None:
        origin = _exact_origin(self.origin)
        if _exact_page_url(self.page_url) != self.page_url or not _same_origin(self.page_url, origin):
            raise BrowserCdpScoringError("browser_target_binding_mismatch", committed=False)
        for value in (
            self.target_id,
            self.frame_id,
            self.execution_context_unique_id,
        ):
            if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
                raise BrowserCdpScoringError("browser_target_binding_mismatch", committed=False)
        if self.browser_context_id is not None and (
            not isinstance(self.browser_context_id, str) or not _IDENTIFIER.fullmatch(self.browser_context_id)
        ):
            raise BrowserCdpScoringError("browser_target_binding_mismatch", committed=False)
        if not isinstance(self.gateway_policy_sha256, str) or not _SHA256.fullmatch(self.gateway_policy_sha256):
            raise BrowserCdpScoringError("browser_gateway_unsealed", committed=False)


@dataclass(frozen=True)
class CTFdScoringAction:
    """One sealed, typed CTFd scoring action."""

    binding: BrowserScoringBinding
    challenge_id: int
    candidate: str = field(repr=False)
    csrf_token: str | None = field(default=None, repr=False)
    timeout_seconds: float = 15.0
    max_response_bytes: int = 256 * 1024

    def __post_init__(self) -> None:
        if isinstance(self.challenge_id, bool) or not isinstance(self.challenge_id, int) or self.challenge_id <= 0:
            raise BrowserCdpScoringError("browser_scoring_action_invalid", committed=False)
        if (
            not isinstance(self.candidate, str)
            or not self.candidate
            or len(self.candidate.encode("utf-8")) > MAX_CANDIDATE_BYTES
        ):
            raise BrowserCdpScoringError("browser_scoring_action_invalid", committed=False)
        if self.csrf_token is not None and (
            not isinstance(self.csrf_token, str) or not _CSRF.fullmatch(self.csrf_token)
        ):
            raise BrowserCdpScoringError("browser_scoring_action_invalid", committed=False)
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(float(self.timeout_seconds))
            or not 0.1 <= float(self.timeout_seconds) <= 120.0
            or isinstance(self.max_response_bytes, bool)
            or not isinstance(self.max_response_bytes, int)
            or not 1 <= self.max_response_bytes <= MAX_RESPONSE_BYTES
        ):
            raise BrowserCdpScoringError("browser_scoring_action_invalid", committed=False)


@dataclass(frozen=True)
class CTFdReadOnlyRequest:
    """One adapter-owned CTFd read through the sealed browser path."""

    binding: BrowserScoringBinding
    operation: str
    csrf_page_path: str = "/challenges"
    timeout_seconds: float = 15.0
    max_response_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        if self.operation not in {*_READ_ONLY_PATHS, "csrf"}:
            raise BrowserCdpScoringError("browser_read_operation_invalid", committed=False)
        if (
            not isinstance(self.csrf_page_path, str)
            or not re.fullmatch(r"/[A-Za-z0-9/_-]{0,255}", self.csrf_page_path)
            or "//" in self.csrf_page_path
        ):
            raise BrowserCdpScoringError("browser_read_operation_invalid", committed=False)
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(float(self.timeout_seconds))
            or not 0.1 <= float(self.timeout_seconds) <= 120.0
            or isinstance(self.max_response_bytes, bool)
            or not isinstance(self.max_response_bytes, int)
            or not 1 <= self.max_response_bytes <= MAX_RESPONSE_BYTES
        ):
            raise BrowserCdpScoringError("browser_read_operation_invalid", committed=False)

    @property
    def path_and_accept(self) -> tuple[str, str]:
        if self.operation == "csrf":
            return self.csrf_page_path, "text/html"
        return _READ_ONLY_PATHS[self.operation]


@dataclass(frozen=True)
class BrowserScoringPreflight:
    """Value-free proof that the adapter-owned page binding is still exact."""

    origin: str
    target_id: str
    browser_context_id: str | None
    gateway_policy_sha256: str


@dataclass(frozen=True)
class BrowserScoringResult:
    """Structured result after exactly one request release."""

    response: dict[str, Any] = field(repr=False)
    verdict: dict[str, Any] = field(repr=False)
    committed: bool = True


@dataclass(frozen=True)
class BrowserReadResult:
    """Bounded browser-origin response for one typed read operation."""

    operation: str
    http_status: int
    headers: dict[str, str]
    document: dict[str, Any] | None = field(default=None, repr=False)
    text: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class BrowserBootstrapResult:
    """Runtime binding plus the bounded account document from controlled navigation."""

    binding: BrowserScoringBinding
    account_document: dict[str, Any] = field(repr=False)
    http_status: int
    headers: dict[str, str]


@dataclass(frozen=True)
class _BoundRequest:
    binding: BrowserScoringBinding
    url: str
    method: str
    accept: str
    body: bytes | None
    csrf_token: str | None
    timeout_seconds: float
    max_response_bytes: int


@dataclass(frozen=True)
class _BrowserHttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes = field(repr=False)


def _exact_origin(value: object) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096:
        raise BrowserCdpScoringError("browser_ctfd_origin_invalid", committed=False)
    try:
        parsed = urllib.parse.urlsplit(value)
        host = canonical_hostname(parsed.hostname or "")
        port = parsed.port or default_port_for_scheme(parsed.scheme.casefold())
    except (UnicodeError, ValueError) as exc:
        raise BrowserCdpScoringError("browser_ctfd_origin_invalid", committed=False) from exc
    if (
        parsed.scheme.casefold() != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or not host
        or not 1 <= port <= 65535
    ):
        raise BrowserCdpScoringError("browser_ctfd_origin_invalid", committed=False)
    authority = host if port == 443 else f"{host}:{port}"
    normalized = f"https://{authority}"
    if value != normalized:
        raise BrowserCdpScoringError("browser_ctfd_origin_invalid", committed=False)
    return normalized


def _exact_page_url(value: object) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 8192:
        raise BrowserCdpScoringError("browser_target_binding_mismatch", committed=False)
    try:
        parsed = urllib.parse.urlsplit(value)
        host = canonical_hostname(parsed.hostname or "")
        port = parsed.port or default_port_for_scheme(parsed.scheme.casefold())
    except (UnicodeError, ValueError) as exc:
        raise BrowserCdpScoringError("browser_target_binding_mismatch", committed=False) from exc
    if (
        parsed.scheme.casefold() != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or not host
        or not parsed.path.startswith("/")
        or not 1 <= port <= 65535
    ):
        raise BrowserCdpScoringError("browser_target_binding_mismatch", committed=False)
    authority = host if port == 443 else f"{host}:{port}"
    return urllib.parse.urlunsplit(("https", authority, parsed.path, parsed.query, ""))


def _same_origin(page_url: str, origin: str) -> bool:
    page = urllib.parse.urlsplit(page_url)
    configured = urllib.parse.urlsplit(origin)
    return canonical_hostname(page.hostname or "") == canonical_hostname(configured.hostname or "") and (
        page.port or 443
    ) == (configured.port or 443)


def _canonical_body(action: CTFdScoringAction) -> bytes:
    return json.dumps(
        {"challenge_id": action.challenge_id, "submission": action.candidate},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _bounded_json_document(data: bytes, *, error: str) -> dict[str, Any]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BrowserCdpScoringError(error, committed=True) from exc
    depth = 0
    separators = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "{[":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise BrowserCdpScoringError(error, committed=True)
        elif character in "}]":
            depth -= 1
            if depth < 0:
                raise BrowserCdpScoringError(error, committed=True)
        elif character in ",:":
            separators += 1
            if separators > MAX_JSON_ITEMS * 2:
                raise BrowserCdpScoringError(error, committed=True)
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise BrowserCdpScoringError(error, committed=True) from exc
    if not isinstance(document, dict):
        raise BrowserCdpScoringError(error, committed=True)
    items = 0
    stack: list[tuple[Any, int]] = [(document, 1)]
    while stack:
        current, current_depth = stack.pop()
        items += 1
        if items > MAX_JSON_ITEMS or current_depth > MAX_JSON_DEPTH:
            raise BrowserCdpScoringError(error, committed=True)
        if isinstance(current, str):
            if len(current.encode("utf-8")) > MAX_JSON_STRING_BYTES:
                raise BrowserCdpScoringError(error, committed=True)
        elif isinstance(current, dict):
            for key, child in current.items():
                if len(str(key).encode("utf-8")) > MAX_JSON_STRING_BYTES:
                    raise BrowserCdpScoringError(error, committed=True)
                stack.append((child, current_depth + 1))
        elif isinstance(current, list):
            stack.extend((child, current_depth + 1) for child in current)
    return document


def parse_ctfd_attempt_verdict(
    response: Mapping[str, Any],
    *,
    http_status: int,
) -> Verdict:
    """Interpret only CTFd's fixed attempt-status contract as scorer truth.

    CTFd's attempt endpoint returns its human explanation in ``data.message``.
    It can say "solved" for partial work or "not accepted" while rate-limited.
    Those words are not scorer truth.  Retain only the documented completion
    statuses, plus the bounded legacy ``correct`` boolean used by compatible
    CTFd deployments, before passing the transport result to the shared parser.
    """

    safe_data: dict[str, Any] = {}
    document = response.get("data") if isinstance(response, Mapping) else None
    data = document.get("data") if isinstance(document, Mapping) and document.get("success") is True else None
    if isinstance(data, Mapping):
        status = data.get("status")
        if isinstance(status, str) and status in _CTFD_ATTEMPT_STATUS_VALUES:
            safe_data["status"] = status
        elif isinstance(data.get("correct"), bool):
            safe_data["correct"] = data["correct"]
    return parse_verdict(
        {"http_status": http_status, "data": safe_data},
        http_status=http_status,
        allow_text_fallback=False,
    )


class _Driver:
    def __init__(self, channel: CdpChannel, *, deadline: float) -> None:
        self.channel = channel
        self.deadline = deadline
        self.committed = False
        self.triggered = False
        self.messages = 0

    def send(self, method: str, params: dict[str, Any]) -> int:
        if method not in _ALLOWED_METHODS:
            self.fail("browser_cdp_command_forbidden")
        try:
            identifier = self.channel.send_command(method, params)
        except (EOFError, OSError) as exc:
            raise BrowserCdpScoringError(
                "browser_cdp_disconnected",
                committed=self.committed or self.triggered,
            ) from exc
        if isinstance(identifier, bool) or not isinstance(identifier, int) or identifier <= 0:
            self.fail("browser_cdp_response_invalid")
        return identifier

    def receive(self) -> dict[str, Any]:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0 or self.messages >= MAX_CDP_MESSAGES:
            raise BrowserCdpScoringError(
                "browser_cdp_timeout",
                committed=self.committed or self.triggered,
            )
        try:
            message = self.channel.receive_message(remaining)
        except TimeoutError as exc:
            raise BrowserCdpScoringError(
                "browser_cdp_timeout",
                committed=self.committed or self.triggered,
            ) from exc
        except (EOFError, OSError) as exc:
            raise BrowserCdpScoringError(
                "browser_cdp_disconnected",
                committed=self.committed or self.triggered,
            ) from exc
        self.messages += 1
        if not isinstance(message, dict):
            self.fail("browser_cdp_response_invalid")
        return message

    def command(
        self,
        method: str,
        params: dict[str, Any],
        *,
        allowed_event: Callable[[dict[str, Any]], bool] | None = None,
    ) -> dict[str, Any]:
        identifier = self.send(method, params)
        while True:
            message = self.receive()
            if message.get("id") == identifier:
                return _command_result(message, committed=self.committed)
            if allowed_event is not None and allowed_event(message):
                continue
            if message.get("id") != identifier:
                self.fail("browser_unexpected_network_effect")

    def fail(self, reason: str) -> None:
        raise BrowserCdpScoringError(reason, committed=self.committed)


def _command_result(message: dict[str, Any], *, committed: bool) -> dict[str, Any]:
    if "error" in message or not isinstance(message.get("result"), dict):
        raise BrowserCdpScoringError("browser_cdp_response_invalid", committed=committed)
    return message["result"]


def _target_info(result: dict[str, Any]) -> dict[str, Any]:
    info = result.get("targetInfo")
    if not isinstance(info, dict):
        raise BrowserCdpScoringError("browser_target_binding_mismatch", committed=False)
    return info


def _matching_page_targets(result: dict[str, Any], origin: str) -> list[dict[str, Any]]:
    target_infos = result.get("targetInfos")
    if not isinstance(target_infos, list) or len(target_infos) > 256:
        raise BrowserCdpScoringError("browser_target_binding_mismatch", committed=False)
    matches: list[dict[str, Any]] = []
    for info in target_infos:
        if not isinstance(info, dict):
            raise BrowserCdpScoringError("browser_target_binding_mismatch", committed=False)
        page_url = info.get("url")
        if info.get("type") != "page" or not isinstance(page_url, str):
            continue
        try:
            normalized_page = _exact_page_url(page_url)
        except BrowserCdpScoringError:
            continue
        if normalized_page == page_url and _same_origin(page_url, origin):
            matches.append(info)
    return matches


def _execution_context_description(message: dict[str, Any]) -> dict[str, Any] | None:
    if message.get("method") != "Runtime.executionContextCreated":
        return None
    params = message.get("params")
    context = params.get("context") if isinstance(params, dict) else None
    return context if isinstance(context, dict) else None


def _context_matches_world(context: dict[str, Any], *, frame_id: str, origin: str) -> bool:
    aux = context.get("auxData")
    return (
        context.get("name") == _SCORING_WORLD_NAME
        and context.get("origin") == origin
        and isinstance(aux, dict)
        and aux.get("frameId") == frame_id
        and aux.get("isDefault") is False
        and aux.get("type") == "isolated"
    )


def _context_unique_id(context: dict[str, Any]) -> str:
    unique_id = context.get("uniqueId")
    if not isinstance(unique_id, str) or not _IDENTIFIER.fullmatch(unique_id):
        raise BrowserCdpScoringError("browser_target_binding_mismatch", committed=False)
    return unique_id


def prepare_browser_scoring_binding(
    channel: CdpChannel,
    origin: str,
    gateway_policy_sha256: str,
    *,
    owned_target_id: str | None = None,
    timeout_seconds: float = 5.0,
) -> BrowserScoringBinding:
    """Derive ephemeral IDs from one adapter-owned exact-origin page.

    The channel must already be attached to the candidate page target. This
    helper performs no browser or platform network request. Its only browser
    state change is creating the fixed isolated execution world when it does
    not already exist. When other same-origin pages exist, ``owned_target_id``
    selects the disposable target without touching the operator's source tab.
    """

    configured_origin = _exact_origin(origin)
    if not isinstance(gateway_policy_sha256, str) or not _SHA256.fullmatch(gateway_policy_sha256):
        raise BrowserCdpScoringError("browser_gateway_unsealed", committed=False)
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(float(timeout_seconds))
        or not 0.1 <= float(timeout_seconds) <= 30.0
    ):
        raise BrowserCdpScoringError("browser_target_binding_mismatch", committed=False)
    driver = _Driver(channel, deadline=time.monotonic() + float(timeout_seconds))
    matches = _matching_page_targets(driver.command("Target.getTargets", {}), configured_origin)
    if owned_target_id is not None:
        if not isinstance(owned_target_id, str) or not _IDENTIFIER.fullmatch(owned_target_id):
            driver.fail("browser_target_binding_mismatch")
        matches = [target for target in matches if target.get("targetId") == owned_target_id]
    if not matches:
        driver.fail("browser_target_missing")
    if len(matches) != 1:
        driver.fail("browser_target_ambiguous")
    selected = matches[0]
    current = _target_info(driver.command("Target.getTargetInfo", {}))
    if any(current.get(key) != selected.get(key) for key in ("targetId", "type", "url", "browserContextId")):
        driver.fail("browser_target_binding_mismatch")
    target_id = selected.get("targetId")
    page_url = selected.get("url")
    browser_context_id = selected.get("browserContextId")
    if (
        not isinstance(target_id, str)
        or not _IDENTIFIER.fullmatch(target_id)
        or not isinstance(page_url, str)
        or _exact_page_url(page_url) != page_url
        or not _same_origin(page_url, configured_origin)
        or (
            browser_context_id is not None
            and (not isinstance(browser_context_id, str) or not _IDENTIFIER.fullmatch(browser_context_id))
        )
    ):
        driver.fail("browser_target_binding_mismatch")
    frame_result = driver.command("Page.getFrameTree", {})
    frame_tree = frame_result.get("frameTree")
    frame = frame_tree.get("frame") if isinstance(frame_tree, dict) else None
    frame_id = frame.get("id") if isinstance(frame, dict) else None
    if (
        not isinstance(frame_id, str)
        or not _IDENTIFIER.fullmatch(frame_id)
        or frame.get("url") != page_url
        or frame.get("parentId") is not None
    ):
        driver.fail("browser_target_binding_mismatch")

    observed_contexts: list[dict[str, Any]] = []

    def collect_context(message: dict[str, Any]) -> bool:
        context = _execution_context_description(message)
        if context is None:
            return False
        observed_contexts.append(context)
        return True

    runtime_enabled = False
    try:
        driver.command("Runtime.enable", {}, allowed_event=collect_context)
        runtime_enabled = True
        matching_contexts = [
            context
            for context in observed_contexts
            if _context_matches_world(context, frame_id=frame_id, origin=configured_origin)
        ]
        if len(matching_contexts) > 1:
            driver.fail("browser_target_binding_mismatch")
        if matching_contexts:
            execution_context_unique_id = _context_unique_id(matching_contexts[0])
        else:
            create_id = driver.send(
                "Page.createIsolatedWorld",
                {
                    "frameId": frame_id,
                    "worldName": _SCORING_WORLD_NAME,
                    "grantUniveralAccess": False,
                },
            )
            created_context_id: int | None = None
            created_context: dict[str, Any] | None = None
            while created_context_id is None or created_context is None:
                message = driver.receive()
                if message.get("id") == create_id:
                    result = _command_result(message, committed=False)
                    value = result.get("executionContextId")
                    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                        driver.fail("browser_target_binding_mismatch")
                    created_context_id = value
                    continue
                context = _execution_context_description(message)
                if context is None:
                    driver.fail("browser_unexpected_network_effect")
                if context.get("id") == created_context_id or (
                    created_context_id is None
                    and _context_matches_world(context, frame_id=frame_id, origin=configured_origin)
                ):
                    if created_context is not None:
                        driver.fail("browser_target_binding_mismatch")
                    created_context = context
            if created_context.get("id") != created_context_id or not _context_matches_world(
                created_context, frame_id=frame_id, origin=configured_origin
            ):
                driver.fail("browser_target_binding_mismatch")
            execution_context_unique_id = _context_unique_id(created_context)
    finally:
        if runtime_enabled:
            try:
                driver.command(
                    "Runtime.disable",
                    {},
                    allowed_event=lambda message: str(message.get("method", "")).startswith("Runtime."),
                )
            except BrowserCdpScoringError:
                pass
    return BrowserScoringBinding(
        origin=configured_origin,
        page_url=page_url,
        target_id=target_id,
        browser_context_id=browser_context_id,
        frame_id=frame_id,
        execution_context_unique_id=execution_context_unique_id,
        gateway_policy_sha256=gateway_policy_sha256,
    )


def bootstrap_owned_browser_target(
    channel: CdpChannel,
    origin: str,
    gateway_policy_sha256: str,
    owned_target_id: str,
    *,
    close_owned_target: OwnedTargetCloser,
    timeout_seconds: float = 15.0,
) -> BrowserBootstrapResult:
    """Navigate an owned ``about:blank`` target under armed fail-closed controls."""

    configured_origin = _exact_origin(origin)
    if not isinstance(owned_target_id, str) or not _IDENTIFIER.fullmatch(owned_target_id):
        raise BrowserCdpScoringError("browser_target_binding_mismatch", committed=False)
    if not isinstance(gateway_policy_sha256, str) or not _SHA256.fullmatch(gateway_policy_sha256):
        raise BrowserCdpScoringError("browser_gateway_unsealed", committed=False)
    if not callable(close_owned_target):
        raise BrowserCdpScoringError("browser_owned_target_close_failed", committed=False)
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(float(timeout_seconds))
        or not 0.1 <= float(timeout_seconds) <= 30.0
    ):
        raise BrowserCdpScoringError("browser_target_binding_mismatch", committed=False)
    driver = _Driver(channel, deadline=time.monotonic() + float(timeout_seconds))
    succeeded = False
    account_url = configured_origin + "/api/v1/users/me"
    try:
        current = _target_info(driver.command("Target.getTargetInfo", {}))
        browser_context_id = current.get("browserContextId")
        if (
            current.get("targetId") != owned_target_id
            or current.get("type") != "page"
            or current.get("url") != "about:blank"
            or (
                browser_context_id is not None
                and (not isinstance(browser_context_id, str) or not _IDENTIFIER.fullmatch(browser_context_id))
            )
        ):
            driver.fail("browser_target_binding_mismatch")
        targets = driver.command("Target.getTargets", {}).get("targetInfos")
        if (
            not isinstance(targets, list)
            or sum(1 for target in targets if isinstance(target, dict) and target.get("targetId") == owned_target_id)
            != 1
        ):
            driver.fail("browser_target_binding_mismatch")
        frame_result = driver.command("Page.getFrameTree", {})
        frame_tree = frame_result.get("frameTree")
        frame = frame_tree.get("frame") if isinstance(frame_tree, dict) else None
        frame_id = frame.get("id") if isinstance(frame, dict) else None
        if (
            not isinstance(frame_id, str)
            or not _IDENTIFIER.fullmatch(frame_id)
            or frame.get("url") != "about:blank"
            or frame.get("parentId") is not None
        ):
            driver.fail("browser_target_binding_mismatch")

        driver.command("Page.setDownloadBehavior", {"behavior": "deny"})
        driver.command("Network.enable", {})
        driver.command("Network.setBypassServiceWorker", {"bypass": True})
        driver.command("Network.setCacheDisabled", {"cacheDisabled": True})
        driver.command("Page.enable", {})
        driver.command(
            "Fetch.enable",
            {
                "patterns": [
                    {"urlPattern": "*", "requestStage": "Request"},
                    {"urlPattern": "*", "requestStage": "Response"},
                ],
                "handleAuthRequests": True,
            },
        )
        navigate_id = driver.send(
            "Page.navigate",
            {
                "url": account_url,
                "referrerPolicy": "noReferrer",
            },
        )
        driver.triggered = True
        navigate_done = False
        frame_navigated = False
        page_loaded = False
        network_finished = False
        request_id: str | None = None
        expected_network_id: str | None = None
        pending_acks: set[int] = set()
        body_id: int | None = None
        continue_response_id: int | None = None
        response_status: int | None = None
        response_headers: dict[str, str] | None = None
        account_document: dict[str, Any] | None = None
        while True:
            message = driver.receive()
            identifier = message.get("id")
            if isinstance(identifier, int) and not isinstance(identifier, bool):
                if identifier == navigate_id:
                    result = _command_result(message, committed=driver.committed or driver.triggered)
                    if result.get("frameId") != frame_id or result.get("errorText") not in {None, ""}:
                        driver.fail("browser_request_interception_mismatch")
                    navigate_done = True
                elif identifier == body_id:
                    response_body = _bounded_body(_command_result(message, committed=True), MAX_RESPONSE_BYTES)
                    account_document = _bounded_json_document(response_body, error="browser_read_response_invalid")
                    continue_response_id = driver.send("Fetch.continueResponse", {"requestId": request_id})
                    pending_acks.add(continue_response_id)
                elif identifier in pending_acks:
                    _command_result(message, committed=driver.committed or driver.triggered)
                    pending_acks.remove(identifier)
                else:
                    driver.fail("browser_unexpected_network_effect")
            else:
                method = message.get("method")
                params = message.get("params")
                if not isinstance(method, str) or not isinstance(params, dict):
                    driver.fail("browser_cdp_response_invalid")
                if method == "Fetch.requestPaused":
                    paused_id = params.get("requestId")
                    paused_request = params.get("request")
                    if not isinstance(paused_id, str) or not paused_id or not isinstance(paused_request, dict):
                        driver.fail("browser_request_interception_mismatch")
                    if "responseStatusCode" not in params:
                        exact = (
                            request_id is None
                            and params.get("frameId") == frame_id
                            and params.get("resourceType") == "Document"
                            and paused_request.get("url") == account_url
                            and paused_request.get("method") == "GET"
                            and paused_request.get("postData") in {None, ""}
                        )
                        if not exact:
                            pending_acks.add(
                                driver.send(
                                    "Fetch.failRequest",
                                    {
                                        "requestId": paused_id,
                                        "errorReason": "BlockedByClient",
                                    },
                                )
                            )
                            driver.fail("browser_unexpected_network_effect")
                        request_id = paused_id
                        network_id = params.get("networkId")
                        if network_id is not None and (
                            not isinstance(network_id, str)
                            or (expected_network_id is not None and network_id != expected_network_id)
                        ):
                            driver.fail("browser_request_interception_mismatch")
                        if isinstance(network_id, str):
                            expected_network_id = network_id
                        pending_acks.add(driver.send("Fetch.continueRequest", {"requestId": paused_id}))
                        driver.committed = True
                    else:
                        status = params.get("responseStatusCode")
                        if (
                            paused_id != request_id
                            or isinstance(status, bool)
                            or not isinstance(status, int)
                            or params.get("frameId") != frame_id
                            or params.get("resourceType") != "Document"
                            or paused_request.get("url") != account_url
                            or paused_request.get("method") != "GET"
                            or params.get("responseErrorReason") is not None
                            or (params.get("networkId") is not None and params.get("networkId") != expected_network_id)
                        ):
                            driver.fail("browser_request_interception_mismatch")
                        if not 200 <= status < 300:
                            driver.fail("browser_request_interception_mismatch")
                        response_status = status
                        response_headers = _response_headers(params.get("responseHeaders"), committed=True)
                        content_type = response_headers.get("content-type", "")
                        if content_type.split(";", 1)[0].strip().casefold() != "application/json":
                            driver.fail("browser_read_response_invalid")
                        body_id = driver.send("Fetch.getResponseBody", {"requestId": paused_id})
                elif method == "Network.requestWillBeSent":
                    network_id = params.get("requestId")
                    network_request = params.get("request")
                    if (
                        not isinstance(network_id, str)
                        or not isinstance(network_request, dict)
                        or network_request.get("url") != account_url
                        or network_request.get("method") != "GET"
                        or params.get("frameId") != frame_id
                        or params.get("type") != "Document"
                    ):
                        driver.fail("browser_unexpected_network_effect")
                    if expected_network_id not in {None, network_id}:
                        driver.fail("browser_unexpected_network_effect")
                    expected_network_id = network_id
                elif method == "Network.requestWillBeSentExtraInfo":
                    if params.get("requestId") != expected_network_id:
                        driver.fail("browser_unexpected_network_effect")
                elif method in {
                    "Network.dataReceived",
                    "Network.responseReceived",
                    "Network.responseReceivedExtraInfo",
                }:
                    if params.get("requestId") != expected_network_id:
                        driver.fail("browser_unexpected_network_effect")
                elif method == "Network.loadingFinished":
                    if params.get("requestId") != expected_network_id:
                        driver.fail("browser_unexpected_network_effect")
                    network_finished = True
                elif method == "Network.loadingFailed":
                    driver.fail("browser_request_interception_mismatch")
                elif method == "Network.policyUpdated" and not params:
                    continue
                elif method == "Page.frameNavigated":
                    navigated = params.get("frame")
                    if (
                        not isinstance(navigated, dict)
                        or navigated.get("id") != frame_id
                        or navigated.get("url") != account_url
                        or navigated.get("parentId") is not None
                    ):
                        driver.fail("browser_target_binding_mismatch")
                    frame_navigated = True
                elif method == "Page.loadEventFired":
                    page_loaded = True
                elif method in {"Page.domContentEventFired", "Page.frameResized"}:
                    continue
                elif method in {
                    "Page.frameRequestedNavigation",
                    "Page.frameStartedNavigating",
                }:
                    if params.get("frameId") != frame_id or params.get("url") != account_url:
                        driver.fail("browser_unexpected_network_effect")
                elif method in {"Page.frameStartedLoading", "Page.frameStoppedLoading"}:
                    if params.get("frameId") != frame_id:
                        driver.fail("browser_unexpected_network_effect")
                elif method in _UNSAFE_NETWORK_EVENTS or method in _UNSAFE_TARGET_EVENTS:
                    driver.fail("browser_unexpected_network_effect")
                else:
                    driver.fail("browser_unexpected_network_effect")
            if (
                navigate_done
                and frame_navigated
                and page_loaded
                and network_finished
                and account_document is not None
                and response_status is not None
                and response_headers is not None
                and continue_response_id is not None
                and not pending_acks
            ):
                break

        def trailing_event(message: dict[str, Any]) -> bool:
            method = str(message.get("method", ""))
            params = message.get("params")
            if method.startswith("Page."):
                return isinstance(params, dict) and params.get("frameId", frame_id) == frame_id
            if method.startswith("Network."):
                return isinstance(params, dict) and params.get("requestId", expected_network_id) == expected_network_id
            return False

        driver.command("Page.disable", {}, allowed_event=trailing_event)
        driver.command("Network.disable", {}, allowed_event=trailing_event)
        binding = prepare_browser_scoring_binding(
            channel,
            configured_origin,
            gateway_policy_sha256,
            owned_target_id=owned_target_id,
            timeout_seconds=min(float(timeout_seconds), 5.0),
        )
        succeeded = True
        return BrowserBootstrapResult(
            binding=binding,
            account_document=account_document,
            http_status=response_status,
            headers=response_headers,
        )
    finally:
        if not succeeded:
            _close_owned_target(
                close_owned_target,
                owned_target_id,
                committed=driver.committed or driver.triggered,
            )


def _is_unrelated_target_event(method: str, params: dict[str, Any], binding: BrowserScoringBinding) -> bool:
    if method not in _UNSAFE_TARGET_EVENTS:
        return False
    info = params.get("targetInfo")
    context_id = info.get("browserContextId") if isinstance(info, dict) else None
    target_type = info.get("type") if isinstance(info, dict) else None
    if context_id == binding.browser_context_id and target_type not in _ACTIVE_TARGET_TYPES:
        return True
    return isinstance(context_id, str) and bool(context_id) and context_id != binding.browser_context_id


def preflight_ctfd_browser_scoring(
    channel: CdpChannel, binding: BrowserScoringBinding, *, timeout_seconds: float = 5.0
) -> BrowserScoringPreflight:
    """Verify the exact target and context without causing browser network I/O."""

    driver = _Driver(channel, deadline=time.monotonic() + timeout_seconds)
    info = _target_info(driver.command("Target.getTargetInfo", {"targetId": binding.target_id}))
    if (
        info.get("targetId") != binding.target_id
        or info.get("type") != "page"
        or info.get("url") != binding.page_url
        or info.get("browserContextId") != binding.browser_context_id
    ):
        driver.fail("browser_target_binding_mismatch")
    target_result = driver.command("Target.getTargets", {})
    target_infos = target_result.get("targetInfos")
    if not isinstance(target_infos, list) or len(target_infos) > 256:
        driver.fail("browser_target_binding_mismatch")
    bound_targets = []
    for candidate in target_infos:
        if not isinstance(candidate, dict):
            driver.fail("browser_target_binding_mismatch")
        if candidate.get("targetId") == binding.target_id:
            bound_targets.append(candidate)
        elif candidate.get("openerId") == binding.target_id and candidate.get("type") in _ACTIVE_TARGET_TYPES:
            driver.fail("browser_target_binding_mismatch")
    if len(bound_targets) != 1 or any(
        bound_targets[0].get(key) != info.get(key) for key in ("targetId", "type", "url", "browserContextId")
    ):
        driver.fail("browser_target_binding_mismatch")
    return BrowserScoringPreflight(
        origin=binding.origin,
        target_id=binding.target_id,
        browser_context_id=binding.browser_context_id,
        gateway_policy_sha256=binding.gateway_policy_sha256,
    )


def _request_matches(event: dict[str, Any], expected: _BoundRequest) -> bool:
    request = event.get("request")
    if not isinstance(request, dict):
        return False
    headers = request.get("headers")
    if not isinstance(headers, dict):
        return False
    normalized_headers: dict[str, str] = {}
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            return False
        lowered = name.casefold()
        if lowered in normalized_headers:
            return False
        normalized_headers[lowered] = value
    expected_csrf = expected.csrf_token
    csrf = normalized_headers.get("csrf-token")
    if expected_csrf is None:
        if csrf is not None:
            return False
    elif csrf != expected_csrf:
        return False
    body = expected.body.decode("utf-8") if expected.body is not None else None
    content_type = normalized_headers.get("content-type")
    return (
        event.get("frameId") == expected.binding.frame_id
        and event.get("resourceType") in _FETCH_RESOURCE_TYPES
        and request.get("url") == expected.url
        and request.get("method") == expected.method
        and normalized_headers.get("accept") == expected.accept
        and (expected.method == "GET" or normalized_headers.get("origin") == expected.binding.origin)
        and (
            (body is None and request.get("postData") in {None, ""} and content_type is None)
            or (
                body is not None
                and str(content_type or "").casefold() == "application/json"
                and request.get("postData") == body
            )
        )
    )


def _response_headers(value: object, *, committed: bool) -> dict[str, str]:
    if not isinstance(value, list) or len(value) > MAX_HEADER_COUNT:
        raise BrowserCdpScoringError("browser_scorer_response_invalid", committed=committed)
    headers: dict[str, str] = {}
    total = 0
    for item in value:
        if not isinstance(item, dict):
            raise BrowserCdpScoringError("browser_scorer_response_invalid", committed=committed)
        name = item.get("name")
        raw = item.get("value")
        if not isinstance(name, str) or not isinstance(raw, str):
            raise BrowserCdpScoringError("browser_scorer_response_invalid", committed=committed)
        lowered = name.strip().casefold()
        value_text = raw.strip()
        if not lowered or any(ord(char) < 0x20 for char in lowered + value_text):
            raise BrowserCdpScoringError("browser_scorer_response_invalid", committed=committed)
        total += len(lowered.encode("utf-8")) + len(value_text.encode("utf-8"))
        if total > MAX_HEADER_BYTES:
            raise BrowserCdpScoringError("browser_scorer_response_invalid", committed=committed)
        if lowered in _SAFE_RESPONSE_HEADERS:
            if lowered in headers:
                raise BrowserCdpScoringError("browser_scorer_response_invalid", committed=committed)
            headers[lowered] = value_text
    return headers


def _bounded_body(result: dict[str, Any], maximum: int) -> bytes:
    value = result.get("body")
    encoded = result.get("base64Encoded")
    if not isinstance(value, str) or not isinstance(encoded, bool):
        raise BrowserCdpScoringError("browser_scorer_response_invalid", committed=True)
    if encoded:
        if len(value) > ((maximum + 2) // 3) * 4 + 4:
            raise BrowserCdpScoringError("browser_scorer_response_too_large", committed=True)
        try:
            body = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise BrowserCdpScoringError("browser_scorer_response_invalid", committed=True) from exc
    else:
        body = value.encode("utf-8")
    if len(body) > maximum:
        raise BrowserCdpScoringError("browser_scorer_response_too_large", committed=True)
    return body


def _runtime_result(result: dict[str, Any]) -> dict[str, Any]:
    if "exceptionDetails" in result:
        raise BrowserCdpScoringError("browser_cdp_runtime_failed", committed=True)
    remote = result.get("result")
    value = remote.get("value") if isinstance(remote, dict) else None
    if not isinstance(value, dict):
        raise BrowserCdpScoringError("browser_cdp_runtime_failed", committed=True)
    return value


def _close_owned_target(
    closer: OwnedTargetCloser,
    target_id: str,
    *,
    committed: bool,
) -> None:
    try:
        closed = closer(target_id, 2.0)
    except (EOFError, OSError, RuntimeError, TimeoutError, TypeError, ValueError) as exc:
        raise BrowserCdpScoringError("browser_owned_target_close_failed", committed=committed) from exc
    if closed is not True:
        raise BrowserCdpScoringError("browser_owned_target_close_failed", committed=committed)


def _execute_browser_request(
    channel: CdpChannel,
    request: _BoundRequest,
    close_owned_target: OwnedTargetCloser,
) -> _BrowserHttpResponse:
    if not callable(close_owned_target):
        raise BrowserCdpScoringError("browser_owned_target_close_failed", committed=False)
    driver = _Driver(channel, deadline=time.monotonic() + float(request.timeout_seconds))
    pending_acks: set[int] = set()
    call_id: int | None = None
    body_id: int | None = None
    request_id: str | None = None
    response_status: int | None = None
    response_headers: dict[str, str] | None = None
    response_body: bytes | None = None
    runtime_value: dict[str, Any] | None = None
    continue_response_id: int | None = None
    network_request_ids: set[str] = set()
    expected_network_id: str | None = None
    try:
        preflight_ctfd_browser_scoring(
            channel,
            request.binding,
            timeout_seconds=min(float(request.timeout_seconds), 5.0),
        )
        driver.command("Network.enable", {})
        driver.command("Network.setBypassServiceWorker", {"bypass": True})
        driver.command("Network.setCacheDisabled", {"cacheDisabled": True})
        driver.command(
            "Target.setAutoAttach",
            {"autoAttach": True, "waitForDebuggerOnStart": True, "flatten": True},
        )
        driver.command(
            "Fetch.enable",
            {
                "patterns": [
                    {"urlPattern": "*", "requestStage": "Request"},
                    {"urlPattern": "*", "requestStage": "Response"},
                ],
                "handleAuthRequests": True,
            },
        )
        global_result = driver.command(
            "Runtime.evaluate",
            {
                "expression": "globalThis",
                "uniqueContextId": request.binding.execution_context_unique_id,
                "returnByValue": False,
                "awaitPromise": False,
                "userGesture": False,
            },
        )
        remote = global_result.get("result")
        object_id = remote.get("objectId") if isinstance(remote, dict) else None
        if not isinstance(object_id, str) or not object_id:
            driver.fail("browser_cdp_runtime_failed")
        call_id = driver.send(
            "Runtime.callFunctionOn",
            {
                "objectId": object_id,
                "functionDeclaration": _FIXED_FETCH_FUNCTION,
                "arguments": [
                    {"value": request.url},
                    {"value": request.method},
                    {"value": request.body.decode("utf-8") if request.body is not None else None},
                    {"value": request.csrf_token or ""},
                    {"value": request.accept},
                    {"value": int(float(request.timeout_seconds) * 1000)},
                ],
                "awaitPromise": True,
                "returnByValue": True,
                "userGesture": False,
            },
        )
        driver.triggered = True
        while True:
            message = driver.receive()
            identifier = message.get("id")
            if isinstance(identifier, int) and not isinstance(identifier, bool):
                if identifier == call_id:
                    runtime_value = _runtime_result(
                        _command_result(
                            message,
                            committed=driver.committed or driver.triggered,
                        )
                    )
                elif identifier == body_id:
                    response_body = _bounded_body(
                        _command_result(message, committed=True),
                        request.max_response_bytes,
                    )
                    continue_response_id = driver.send("Fetch.continueResponse", {"requestId": request_id})
                    pending_acks.add(continue_response_id)
                elif identifier in pending_acks:
                    _command_result(
                        message,
                        committed=driver.committed or driver.triggered,
                    )
                    pending_acks.remove(identifier)
                else:
                    driver.fail("browser_unexpected_network_effect")
            else:
                method = message.get("method")
                params = message.get("params")
                if not isinstance(method, str) or not isinstance(params, dict):
                    driver.fail("browser_cdp_response_invalid")
                if method == "Fetch.requestPaused":
                    paused_id = params.get("requestId")
                    if not isinstance(paused_id, str) or not paused_id:
                        driver.fail("browser_request_interception_mismatch")
                    if "responseStatusCode" not in params:
                        if driver.committed or not _request_matches(params, request):
                            pending_acks.add(
                                driver.send(
                                    "Fetch.failRequest",
                                    {
                                        "requestId": paused_id,
                                        "errorReason": "BlockedByClient",
                                    },
                                )
                            )
                            driver.fail("browser_unexpected_network_effect")
                        request_id = paused_id
                        paused_network_id = params.get("networkId")
                        if paused_network_id is not None and (
                            not isinstance(paused_network_id, str)
                            or (expected_network_id is not None and paused_network_id != expected_network_id)
                        ):
                            driver.fail("browser_request_interception_mismatch")
                        if isinstance(paused_network_id, str):
                            expected_network_id = paused_network_id
                        pending_acks.add(driver.send("Fetch.continueRequest", {"requestId": paused_id}))
                        driver.committed = True
                    else:
                        status = params.get("responseStatusCode")
                        paused_request = params.get("request")
                        if (
                            not driver.committed
                            or paused_id != request_id
                            or isinstance(status, bool)
                            or not isinstance(status, int)
                            or not isinstance(paused_request, dict)
                            or paused_request.get("url") != request.url
                            or paused_request.get("method") != request.method
                            or params.get("frameId") != request.binding.frame_id
                            or params.get("resourceType") not in _FETCH_RESOURCE_TYPES
                            or params.get("responseErrorReason") is not None
                            or (params.get("networkId") is not None and params.get("networkId") != expected_network_id)
                        ):
                            driver.fail("browser_request_interception_mismatch")
                        if 300 <= status < 400:
                            driver.fail("browser_request_interception_mismatch")
                        response_status = status
                        response_headers = _response_headers(params.get("responseHeaders"), committed=True)
                        body_id = driver.send("Fetch.getResponseBody", {"requestId": paused_id})
                elif method == "Network.requestWillBeSent":
                    network_id = params.get("requestId")
                    network_request = params.get("request")
                    if not isinstance(network_id, str) or not network_id or not isinstance(network_request, dict):
                        driver.fail("browser_unexpected_network_effect")
                    network_request_ids.add(network_id)
                    if len(network_request_ids) > 8:
                        driver.fail("browser_unexpected_network_effect")
                    if (
                        network_request.get("url") == request.url
                        and network_request.get("method") == request.method
                        and params.get("frameId") == request.binding.frame_id
                        and params.get("type") == "Fetch"
                    ):
                        if expected_network_id not in {None, network_id}:
                            driver.fail("browser_unexpected_network_effect")
                        expected_network_id = network_id
                elif method == "Network.requestWillBeSentExtraInfo":
                    network_id = params.get("requestId")
                    if not isinstance(network_id, str) or not network_id:
                        driver.fail("browser_unexpected_network_effect")
                    network_request_ids.add(network_id)
                    if len(network_request_ids) > 8:
                        driver.fail("browser_unexpected_network_effect")
                elif method in {
                    "Network.dataReceived",
                    "Network.loadingFinished",
                    "Network.responseReceived",
                    "Network.responseReceivedExtraInfo",
                }:
                    if params.get("requestId") != expected_network_id:
                        driver.fail("browser_unexpected_network_effect")
                elif method == "Network.loadingFailed":
                    if params.get("requestId") == expected_network_id:
                        driver.fail("browser_request_interception_mismatch")
                    driver.fail("browser_unexpected_network_effect")
                elif method == "Network.policyUpdated" and not params:
                    continue
                elif method in _UNSAFE_NETWORK_EVENTS:
                    driver.fail("browser_unexpected_network_effect")
                elif method in _UNSAFE_TARGET_EVENTS:
                    if _is_unrelated_target_event(method, params, request.binding):
                        continue
                    driver.fail("browser_unexpected_network_effect")
                else:
                    driver.fail("browser_unexpected_network_effect")
            if (
                runtime_value is not None
                and response_body is not None
                and continue_response_id is not None
                and not pending_acks
                and network_request_ids.issubset({expected_network_id})
            ):
                break
        if response_status is None or response_headers is None:
            driver.fail("browser_scorer_response_invalid")
        if (
            runtime_value.get("url") != request.url
            or runtime_value.get("status") != response_status
            or runtime_value.get("redirected") is not False
            or runtime_value.get("type") not in {"basic", "cors"}
        ):
            driver.fail("browser_request_interception_mismatch")
        content_type = response_headers.get("content-type", "")
        if content_type.split(";", 1)[0].strip().casefold() != request.accept:
            driver.fail("browser_scorer_response_invalid")
        runtime_content_type = runtime_value.get("contentType")
        if (
            not isinstance(runtime_content_type, str)
            or runtime_content_type.split(";", 1)[0].strip().casefold() != request.accept
        ):
            driver.fail("browser_request_interception_mismatch")
        return _BrowserHttpResponse(
            status=response_status,
            headers={name: value for name, value in sorted(response_headers.items()) if name in _SAFE_RESPONSE_HEADERS},
            body=response_body,
        )
    except BrowserCdpScoringError:
        raise
    except (TypeError, ValueError) as exc:
        raise BrowserCdpScoringError(
            "browser_cdp_response_invalid",
            committed=driver.committed or driver.triggered,
        ) from exc
    finally:
        _close_owned_target(
            close_owned_target,
            request.binding.target_id,
            committed=driver.committed or driver.triggered,
        )


def execute_ctfd_browser_read(
    channel: CdpChannel,
    request: CTFdReadOnlyRequest,
    *,
    close_owned_target: OwnedTargetCloser,
) -> BrowserReadResult:
    """Perform one CTFd GET, then require confirmed owned-target destruction."""

    path, accept = request.path_and_accept
    response = _execute_browser_request(
        channel,
        _BoundRequest(
            binding=request.binding,
            url=request.binding.origin + path,
            method="GET",
            accept=accept,
            body=None,
            csrf_token=None,
            timeout_seconds=float(request.timeout_seconds),
            max_response_bytes=request.max_response_bytes,
        ),
        close_owned_target,
    )
    if not 200 <= response.status < 300:
        raise BrowserCdpScoringError("browser_read_response_invalid", committed=True)
    if accept == "application/json":
        document = _bounded_json_document(response.body, error="browser_read_response_invalid")
        return BrowserReadResult(
            operation=request.operation,
            http_status=response.status,
            headers=response.headers,
            document=document,
        )
    try:
        text = response.body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BrowserCdpScoringError("browser_read_response_invalid", committed=True) from exc
    return BrowserReadResult(
        operation=request.operation,
        http_status=response.status,
        headers=response.headers,
        text=text,
    )


def execute_ctfd_browser_scoring(
    channel: CdpChannel,
    action: CTFdScoringAction,
    *,
    close_owned_target: OwnedTargetCloser,
) -> BrowserScoringResult:
    """Release one reviewed attempt, then destroy the owned target before return."""

    body = _canonical_body(action)
    browser_response = _execute_browser_request(
        channel,
        _BoundRequest(
            binding=action.binding,
            url=action.binding.origin + ATTEMPT_PATH,
            method="POST",
            accept="application/json",
            body=body,
            csrf_token=action.csrf_token,
            timeout_seconds=float(action.timeout_seconds),
            max_response_bytes=action.max_response_bytes,
        ),
        close_owned_target,
    )
    document = _bounded_json_document(browser_response.body, error="browser_scorer_response_invalid")
    response = {
        "http_status": browser_response.status,
        "headers": browser_response.headers,
        "data": document,
    }
    verdict = parse_ctfd_attempt_verdict(
        response,
        http_status=browser_response.status,
    )
    return BrowserScoringResult(response=response, verdict=verdict.to_dict())
