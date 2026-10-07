from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
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
from rookery.portable.environment import (
    EnvClass,
    EnvironmentPolicyError,
    EnvKey,
    EnvSource,
    build_child_environment,
    classify_environment_name,
    parse_name_array,
    purpose_policy,
)
from rookery.portable.network_policy import ExplicitNetworkPolicy
from rookery.portable.scope import check_url, open_scoped_url
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
_CTFD_NETWORK_SELECTOR = "CTFD_NETWORK_ENV_KEYS"
_CTFD_NETWORK_CLASSES = frozenset(
    {EnvClass.PROXY_CREDENTIAL, EnvClass.CA_TRUST_PATH}
)


def privacy_safe_response_headers(headers: Any) -> dict[str, str]:
    """Keep compact diagnostic headers without persisting session material."""

    if not headers:
        return {}
    try:
        items = headers.items()
    except AttributeError:
        return {}
    safe: dict[str, str] = {}
    for raw_name, raw_value in items:
        name = str(raw_name).strip().lower()
        if name in _SENSITIVE_RESPONSE_HEADERS:
            safe[name] = "[redacted]"
        elif name in _SAFE_RESPONSE_HEADERS:
            value = str(raw_value).replace("\r", " ").replace("\n", " ").strip()
            encoded = value.encode("utf-8", errors="replace")
            if len(encoded) > _MAX_SAVED_HEADER_BYTES:
                value = (
                    encoded[:_MAX_SAVED_HEADER_BYTES].decode("utf-8", errors="ignore")
                    + "…"
                )
            safe[name] = value
    return dict(sorted(safe.items()))


def _open_scoped(
    scope: dict[str, Any],
    request: urllib.request.Request,
    *,
    timeout: int,
    transport: Any,
):
    """Open through the shared direct, DNS-pinned transport.

    ``open_scoped_url`` checks the initial request and every redirect hop before
    issuing it.  The transport is supplied by ``ExplicitNetworkPolicy`` so
    ambient proxy/CA configuration and post-admission DNS cannot take effect.
    """

    return open_scoped_url(
        scope,
        request,
        timeout=timeout,
        platform=True,
        transport=transport,
    )


def _response_header(headers: Any, name: str) -> str:
    """Return one response header without preserving response contents."""

    if not headers:
        return ""
    try:
        value = headers.get(name)
    except AttributeError:
        return ""
    return value.strip() if isinstance(value, str) else ""


def _response_status(response: Any) -> int:
    """Read an HTTP status from standard urllib response implementations."""

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
    """Describe a rejected HTTP response without including its body or secrets."""

    if _response_header(headers, "CF-Mitigated").casefold() == "challenge":
        return f"HTTP {status} Cloudflare challenge"
    return f"HTTP {status}"


def _ctfd_challenges(response: Any, response_limit: int) -> list[dict[str, Any]]:
    """Validate the CTFd inventory envelope before normalizing its challenges."""

    status = _response_status(response)
    if not 200 <= status < 300:
        raise RuntimeError(_http_failure_detail(status, getattr(response, "headers", None)))
    content_type = _response_header(getattr(response, "headers", None), "Content-Type")
    if content_type.split(";", 1)[0].strip().casefold() != "application/json":
        raise RuntimeError(f"HTTP {status} expected application/json")
    raw = bounded_response_bytes(response, response_limit)
    if not raw:
        raise RuntimeError(f"HTTP {status} empty response")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"HTTP {status} invalid JSON response") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"HTTP {status} invalid CTFd response shape")
    if payload.get("success") is not True:
        raise RuntimeError(f"HTTP {status} CTFd response was unsuccessful")
    challenges = payload.get("data")
    if not isinstance(challenges, list) or not all(
        isinstance(challenge, dict) for challenge in challenges
    ):
        raise RuntimeError(f"HTTP {status} invalid CTFd response shape")
    return challenges


def _unhealthy_capabilities(
    availability: str,
    freshness: str,
    detail: str,
) -> list[CapabilityHealth]:
    """Describe a shared inventory failure across all required CTFd capabilities."""

    return [
        CapabilityHealth(
            "platform_inventory",
            availability,
            "unhealthy",
            freshness,
            "read-only",
            (),
            detail,
        ),
        CapabilityHealth(
            "challenge_details",
            availability,
            "unhealthy",
            freshness,
            "read-only",
            (),
            detail,
        ),
        CapabilityHealth(
            "scoring",
            availability,
            "unhealthy",
            freshness,
            "reviewer-only",
            ("flag", "free_text"),
            detail,
        ),
    ]


class CTFdAdapter(Adapter):
    id = "ctfd"

    def _request_configuration(
        self, *, require_token: bool
    ) -> tuple[str, str, Any]:
        """Resolve one CTFd request's URL, token, and declared transport."""

        configured = self.config.get("token_env", "CTFD_TOKEN")
        if not isinstance(configured, str) or not configured:
            raise RuntimeError("CTFd token_env must be an exact environment key name")
        token_env = configured
        try:
            token_class = classify_environment_name(token_env)
        except EnvironmentPolicyError as exc:
            raise RuntimeError("CTFd token_env must be an exact environment key name") from exc
        if token_class not in {EnvClass.ADAPTER_SECRET, EnvClass.UNKNOWN_EXPLICIT}:
            raise RuntimeError(
                f"CTFd token_env forbids class {token_class.value}: {token_env}"
            )
        resolved = self._resolve_local_environment(
            (
                EnvKey(
                    "CTFD_URL",
                    EnvClass.ROOKERY_CONFIG,
                    sources=(EnvSource.DOTENV, EnvSource.PARENT),
                ),
                EnvKey(
                    token_env,
                    token_class,
                    required=require_token,
                    sources=(EnvSource.DOTENV, EnvSource.PARENT),
                ),
                EnvKey(
                    _CTFD_NETWORK_SELECTOR,
                    EnvClass.ROOKERY_CONFIG,
                    sources=(EnvSource.DOTENV, EnvSource.PARENT),
                ),
            )
        )
        raw_network_names = resolved.get(_CTFD_NETWORK_SELECTOR, "")
        try:
            network_names = parse_name_array(
                raw_network_names,
                label=_CTFD_NETWORK_SELECTOR,
            )
        except EnvironmentPolicyError as exc:
            raise RuntimeError(str(exc)) from exc
        network_declarations: list[EnvKey] = []
        for name in network_names:
            classification = classify_environment_name(name)
            if classification not in _CTFD_NETWORK_CLASSES:
                raise RuntimeError(
                    f"{_CTFD_NETWORK_SELECTOR} forbids class "
                    f"{classification.value}: {name}"
                )
            network_declarations.append(
                EnvKey(
                    name,
                    classification,
                    required=True,
                    sources=(EnvSource.DOTENV, EnvSource.PARENT),
                )
            )
        try:
            network_environment = build_child_environment(
                self.root,
                policy=purpose_policy(
                    "ctfd-network",
                    network_declarations,
                    allowed_classes=_CTFD_NETWORK_CLASSES,
                ),
            )
        except EnvironmentPolicyError as exc:
            raise RuntimeError(str(exc)) from exc
        base_config = self.config.get("base_url")
        if base_config is not None and not isinstance(base_config, str):
            raise RuntimeError("CTFd base_url must be a string")
        base = (
            str(base_config).strip()
            if isinstance(base_config, str) and base_config.strip() not in {"", "unknown"}
            else str(resolved.get("CTFD_URL") or "").strip()
        )
        try:
            network_policy = ExplicitNetworkPolicy.from_child_environment(
                network_environment,
            )
        except EnvironmentPolicyError as exc:
            raise RuntimeError(str(exc)) from exc
        return (
            base,
            resolved.get(token_env, "") or "",
            network_policy.scoped_transport(self.scope, platform=True),
        )

    def _response_limit(self) -> int:
        value = int(self.config.get("max_response_bytes", DEFAULT_ADAPTER_OUTPUT_BYTES))
        if value <= 0 or value > MAX_ADAPTER_OUTPUT_BYTES:
            raise RuntimeError("CTFd response byte limit is outside supported range")
        return value

    def sync(self) -> dict[str, Any]:
        try:
            base, token_value, transport = self._request_configuration(
                require_token=False
            )
        except RuntimeError as exc:
            caps = _unhealthy_capabilities("configured", "unknown", str(exc))
            return normalized_snapshot(self.id, caps, [])
        base = base.rstrip("/")
        if not base or base == "unknown":
            caps = [
                CapabilityHealth(
                    "platform_inventory",
                    "configured",
                    "unknown",
                    "unknown",
                    "read-only",
                    (),
                ),
                CapabilityHealth(
                    "challenge_details",
                    "configured",
                    "unknown",
                    "unknown",
                    "read-only",
                    (),
                    "base URL unresolved",
                ),
                CapabilityHealth(
                    "scoring",
                    "configured",
                    "unknown",
                    "unknown",
                    "reviewer-only",
                    ("flag", "free_text"),
                    "base URL unresolved",
                ),
            ]
            return normalized_snapshot(self.id, caps, [])
        decision = check_url(self.scope, base, platform=True)
        if not decision.allowed:
            caps = _unhealthy_capabilities("blocked", "unknown", decision.reason)
            return normalized_snapshot(self.id, caps, [])
        request = urllib.request.Request(base + "/api/v1/challenges")
        if token_value:
            request.add_header("Authorization", f"Token {token_value}")
        try:
            with _open_scoped(
                self.scope,
                request,
                timeout=int(self.config.get("timeout", 30)),
                transport=transport,
            ) as response:
                challenges = _ctfd_challenges(response, self._response_limit())
            caps = [
                CapabilityHealth(
                    "platform_inventory",
                    "available",
                    "healthy",
                    iso_now(),
                    "read-only",
                    (),
                ),
                CapabilityHealth(
                    "challenge_details",
                    "available",
                    "healthy",
                    iso_now(),
                    "read-only",
                    (),
                ),
                CapabilityHealth(
                    "release_changes",
                    "available",
                    "healthy",
                    iso_now(),
                    "read-only",
                    (),
                ),
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
        except urllib.error.HTTPError as exc:
            caps = _unhealthy_capabilities(
                "available",
                "stale",
                _http_failure_detail(exc.code, exc.headers),
            )
            return normalized_snapshot(self.id, caps, [])
        except (OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
            caps = _unhealthy_capabilities("available", "stale", str(exc))
            return normalized_snapshot(self.id, caps, [])

    def execute_action(
        self, envelope: dict[str, Any], evidence_root: Path
    ) -> dict[str, Any]:
        # Resolve the required credential before scope evaluation, request
        # construction, or transport so a missing token cannot trigger I/O.
        base, token, transport = self._request_configuration(require_token=True)
        base = base.rstrip("/")
        if not base or base == "unknown":
            raise RuntimeError("CTFd base URL unresolved")
        decision = check_url(self.scope, base, platform=True)
        if not decision.allowed:
            raise RuntimeError(decision.reason)
        body = json.dumps(
            {
                "challenge_id": int(envelope["objective_id"]),
                "submission": envelope.get("exact_value", ""),
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            base + "/api/v1/challenges/attempt",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        request.add_header("Authorization", f"Token {token}")
        try:
            # Proxy-selected effects are rejected before submission evidence
            # exists; an exact direct NO_PROXY rule is the only bypass.
            transport.preflight_url(request.full_url)
        except Exception as exc:
            raise RuntimeError(str(exc)) from exc
        evidence_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            os.chmod(evidence_root, 0o700)
        atomic_write_json(
            evidence_root / "request.json",
            {
                "url": request.full_url,
                "body": json.loads(body),
                "objective_id": envelope["objective_id"],
                "candidate": envelope.get("exact_value", ""),
            },
            mode=0o600,
        )
        try:
            with _open_scoped(
                self.scope,
                request,
                timeout=int(self.config.get("timeout", 30)),
                transport=transport,
            ) as response:
                raw = bounded_response_bytes(response, self._response_limit())
                obj = json.loads(raw.decode("utf-8"))
                status = response.status
                response_headers = privacy_safe_response_headers(response.headers)
        except urllib.error.HTTPError as exc:
            raw = bounded_response_bytes(exc, self._response_limit())
            try:
                obj = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                obj = {"message": raw.decode("utf-8", errors="replace")}
            status = exc.code
            response_headers = privacy_safe_response_headers(exc.headers)
        response_obj = {
            "http_status": status,
            "headers": response_headers,
            "data": obj,
        }
        atomic_write_json(evidence_root / "response.json", response_obj, mode=0o600)
        verdict = parse_verdict(response_obj, http_status=status)
        return {
            "response": response_obj,
            "response_path": str(evidence_root / "response.json"),
            "verdict": verdict.to_dict(),
        }
