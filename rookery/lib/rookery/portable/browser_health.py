"""Read-only health check for a forwarded Rookery browser bridge."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .browser_gateway_policy import policy_sha256
from .baseline import configuration_digest
from .environment import (
    EnvironmentPolicyError,
    verify_browser_cdp_endpoint,
    verify_browser_gateway_endpoint,
)


class BrowserHealthError(ValueError):
    """A stable value-free browser health failure."""


def browser_health(
    *,
    baseline: Path,
    policy: Path,
    cdp_url: str,
    gateway_status_url: str,
    bridge_metadata: Path | None = None,
) -> dict[str, object]:
    try:
        baseline_value = json.loads(baseline.read_text(encoding="utf-8"))
        policy_value = json.loads(policy.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrowserHealthError("browser_health_binding_invalid") from exc
    if not isinstance(baseline_value, dict) or not isinstance(policy_value, dict):
        raise BrowserHealthError("browser_health_binding_invalid")
    baseline_digest = baseline_value.get("configuration_digest")
    if (
        not isinstance(baseline_digest, str)
        or baseline_digest != configuration_digest(baseline_value)
        or policy_value.get("baseline_configuration_digest") != baseline_digest
    ):
        raise BrowserHealthError("browser_health_baseline_mismatch")
    expected_policy = policy_sha256(policy_value)
    bridge_release: dict[str, object] | None = None
    if bridge_metadata is not None:
        try:
            bridge_value = json.loads(bridge_metadata.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BrowserHealthError("browser_health_bridge_binding_invalid") from exc
        baseline_release = baseline_value.get("release")
        candidate_release = bridge_value.get("release") if isinstance(bridge_value, dict) else None
        if not isinstance(baseline_release, dict) or not isinstance(candidate_release, dict):
            raise BrowserHealthError("browser_health_bridge_binding_invalid")
        comparisons = (
            (baseline_release.get("version"), candidate_release.get("version")),
            (baseline_release.get("archive_sha256"), candidate_release.get("archive_sha256")),
            (baseline_release.get("manifest_sha256"), candidate_release.get("manifest_sha256")),
        )
        if any(
            not isinstance(left, str) or not left or left != right
            for left, right in comparisons
        ):
            raise BrowserHealthError("browser_health_bridge_release_mismatch")
        bridge_release = {
            "version": candidate_release["version"],
            "archive_sha256": candidate_release["archive_sha256"],
            "manifest_sha256": candidate_release["manifest_sha256"],
        }
    try:
        verify_browser_cdp_endpoint(cdp_url)
        gateway = verify_browser_gateway_endpoint(
            gateway_status_url,
            expected_policy_sha256=expected_policy,
            expected_expires_at=str(policy_value.get("expires_at") or ""),
        )
    except EnvironmentPolicyError as exc:
        raise BrowserHealthError(str(exc)) from exc
    result: dict[str, object] = {
        "ok": True,
        "cdp_ready": True,
        "policy_sha256": expected_policy,
        "gateway_boot_nonce": gateway.boot_nonce,
        "gateway_expires_at": gateway.expires_at,
        "baseline_configuration_digest": baseline_digest,
    }
    if bridge_release is not None:
        result["bridge_release"] = bridge_release
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--cdp-url", default="http://127.0.0.1:9001")
    parser.add_argument("--gateway-status-url", default="http://127.0.0.1:9003")
    parser.add_argument("--bridge-metadata", type=Path)
    args = parser.parse_args(argv)
    try:
        result = browser_health(
            baseline=args.baseline,
            policy=args.policy,
            cdp_url=args.cdp_url,
            gateway_status_url=args.gateway_status_url,
            bridge_metadata=args.bridge_metadata,
        )
    except BrowserHealthError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
