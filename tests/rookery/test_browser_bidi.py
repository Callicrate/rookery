from __future__ import annotations

import runpy
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

# ruff: noqa: E402
from rookery.portable.browser_bidi import BrowserBidiError
from rookery.portable.cli import startup_checks
from rookery.portable.environment import (
    EnvironmentPolicyError,
    browser_cdp_required,
    resolve_browser_bidi_endpoint,
    verify_required_browser_bidi,
)
from rookery.portable.event_env import _required_environment


class _FakeFirefoxSession:
    contexts_value: list[dict[str, Any]] = [
        {"context": "context-1", "parent": None, "url": "https://fixture.invalid/challenges"}
    ]
    partition_origin: str | None = "https://fixture.invalid"
    include_partition_origin = True
    closed = False

    def __init__(self, endpoint: str) -> None:
        if endpoint != "ws://127.0.0.1:9223/session":
            raise AssertionError("wrong BiDi endpoint")

    def __enter__(self) -> _FakeFirefoxSession:
        return self

    def __exit__(self, *_args: object) -> None:
        type(self).closed = True

    def contexts(self) -> list[dict[str, Any]]:
        return self.contexts_value

    def user_agent(self, context: str) -> str:
        if context != "context-1":
            raise AssertionError("wrong context")
        return "Mozilla/5.0 Firefox/140.0"

    def cookies(self, context: str) -> dict[str, Any]:
        if context != "context-1":
            raise AssertionError("wrong context")
        partition_key = {"userContext": "default"}
        if self.include_partition_origin:
            partition_key["sourceOrigin"] = self.partition_origin
        return {
            "partitionKey": partition_key,
            "cookies": [
                {
                    "name": "unrelated",
                    "value": {"type": "string", "value": "other"},
                    "domain": "other.invalid",
                    "path": "/",
                    "secure": True,
                },
                {
                    "name": "session",
                    "value": {"type": "string", "value": "fixture-secret"},
                    "domain": "fixture.invalid",
                    "path": "/",
                    "secure": True,
                },
            ],
        }


class BrowserBidiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter_namespace = runpy.run_path(
            str(ROOKERY_ROOT / "adapters" / "ctfd_browser" / "adapter.py")
        )
        _FakeFirefoxSession.contexts_value = [
            {"context": "context-1", "parent": None, "url": "https://fixture.invalid/challenges"}
        ]
        _FakeFirefoxSession.partition_origin = "https://fixture.invalid"
        _FakeFirefoxSession.include_partition_origin = True
        _FakeFirefoxSession.closed = False

    def test_bidi_endpoint_must_be_exact_ipv4_loopback_session(self) -> None:
        self.assertEqual(
            resolve_browser_bidi_endpoint("ws://127.0.0.1:9223/session"),
            ("ws://127.0.0.1:9223/session", 9223),
        )
        for endpoint in (
            "ws://0.0.0.0:9223/session",
            "ws://localhost:9223/session",
            "wss://127.0.0.1:9223/session",
            "ws://127.0.0.1:9223/other",
            "ws://127.0.0.1:9223/session?token=secret",
            "ws://user:secret@127.0.0.1:9223/session",
        ):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(EnvironmentPolicyError):
                    resolve_browser_bidi_endpoint(endpoint)

    def test_ctfd_descriptor_requires_the_selected_browser_endpoint(self) -> None:
        descriptor = json.loads(
            (ROOKERY_ROOT / "adapters" / "ctfd_browser" / "adapter.json").read_text(encoding="utf-8")
        )
        declared = {item["name"] for item in descriptor["environment_schema"]}
        raw = {
            "CTFD_URL": "https://fixture.invalid",
            "ADAPTER_CONFIG_BASE_URL": "https://fixture.invalid",
            "ADAPTER_CONFIG_SCORING_MODE": "user",
            "ADAPTER_CONFIG_EXPECTED_ACCOUNT_ID": "42",
            "BROWSER_MODE": "bidi",
            "BROWSER_BIDI_URL": "ws://127.0.0.1:9223/session",
        }
        self.assertEqual(_required_environment(descriptor, declared, raw), ())
        self.assertIn(
            "BROWSER_MODE",
            _required_environment(descriptor, declared, {**raw, "BROWSER_MODE": "auto"}),
        )
        self.assertIn(
            "BROWSER_CDP_URL",
            _required_environment(descriptor, declared, {**raw, "BROWSER_MODE": "cdp"}),
        )

    def test_bidi_mode_requires_bidi_readiness_without_cdp(self) -> None:
        preparation = {
            "BROWSER_MODE": "bidi",
            "BROWSER_BIDI_URL": "ws://127.0.0.1:9223/session",
        }
        self.assertFalse(browser_cdp_required(preparation, {"adapter": {"id": "ctfd_browser"}}))
        with mock.patch("rookery.portable.browser_bidi.verify_browser_bidi_endpoint") as verify:
            verify_required_browser_bidi(preparation)
        verify.assert_called_once_with("ws://127.0.0.1:9223/session")

    def test_bidi_cookie_relay_uses_selected_context_partition(self) -> None:
        reader = self.adapter_namespace["_read_bidi_browser_session"]
        with mock.patch.dict(reader.__globals__, {"FirefoxBidiSession": _FakeFirefoxSession}):
            session = reader(
                "ws://127.0.0.1:9223/session",
                "https://fixture.invalid",
                target_id=None,
            )
        self.assertTrue(_FakeFirefoxSession.closed)
        self.assertEqual(session.target_id, "context-1")
        self.assertEqual(session.cookie_header, "session=fixture-secret")
        self.assertNotIn("fixture-secret", repr(session))

    def test_bidi_cookie_relay_accepts_optional_partition_origin(self) -> None:
        reader = self.adapter_namespace["_read_bidi_browser_session"]
        _FakeFirefoxSession.include_partition_origin = False
        with mock.patch.dict(reader.__globals__, {"FirefoxBidiSession": _FakeFirefoxSession}):
            session = reader(
                "ws://127.0.0.1:9223/session",
                "https://fixture.invalid",
                target_id=None,
            )
        self.assertEqual(session.target_id, "context-1")
        self.assertEqual(session.cookie_header, "session=fixture-secret")

    def test_bidi_ambiguous_context_and_partition_drift_fail_closed(self) -> None:
        reader = self.adapter_namespace["_read_bidi_browser_session"]
        _FakeFirefoxSession.contexts_value.append(
            {"context": "context-2", "parent": None, "url": "https://fixture.invalid/scoreboard"}
        )
        with mock.patch.dict(reader.__globals__, {"FirefoxBidiSession": _FakeFirefoxSession}):
            with self.assertRaisesRegex(BrowserBidiError, "context_ambiguous"):
                reader("ws://127.0.0.1:9223/session", "https://fixture.invalid", target_id=None)
        _FakeFirefoxSession.contexts_value.pop()
        _FakeFirefoxSession.partition_origin = "https://other.invalid"
        with mock.patch.dict(reader.__globals__, {"FirefoxBidiSession": _FakeFirefoxSession}):
            with self.assertRaisesRegex(BrowserBidiError, "partition_invalid"):
                reader("ws://127.0.0.1:9223/session", "https://fixture.invalid", target_id=None)
        _FakeFirefoxSession.partition_origin = None
        with mock.patch.dict(reader.__globals__, {"FirefoxBidiSession": _FakeFirefoxSession}):
            with self.assertRaisesRegex(BrowserBidiError, "partition_invalid"):
                reader("ws://127.0.0.1:9223/session", "https://fixture.invalid", target_id=None)

    def test_ctfd_adapter_selects_bidi_without_using_cdp(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.joinpath(".env").write_text(
                "BROWSER_MODE=bidi\nBROWSER_BIDI_URL=ws://127.0.0.1:9223/session\n",
                encoding="utf-8",
            )
            adapter = self.adapter_namespace["CTFdBrowserAdapter"](
                root,
                {
                    "adapter": {
                        "id": "ctfd_browser",
                        "config": {
                            "base_url": "https://fixture.invalid",
                            "scoring_mode": "user",
                            "expected_account_id": "42",
                        },
                    }
                },
                {
                    "acknowledged": True,
                    "generation": 1,
                    "expires_at": "unknown",
                    "allowed_hosts": [],
                    "allowed_cidrs": [],
                    "allowed_ports": [],
                    "allowed_protocols": ["https"],
                    "allowed_file_origins": [],
                    "platform_hosts": ["fixture.invalid"],
                    "max_attachment_bytes": 4096,
                },
            )
            lease = self.adapter_namespace["_SessionLease"](
                transport="token",
                base_url="https://fixture.invalid",
                account_id="42",
                team_id=None,
                expires_at=time.monotonic() + 30,
            )
            probe = mock.Mock()
            cdp_probe = mock.Mock()
            with (
                mock.patch.dict(
                    adapter.sync.__globals__,
                    {
                        "verify_browser_bidi_endpoint": probe,
                        "verify_browser_cdp_endpoint": cdp_probe,
                    },
                ),
                mock.patch.object(adapter, "_new_lease", return_value=(lease, [])),
            ):
                snapshot = adapter.sync()
            probe.assert_called_once_with("ws://127.0.0.1:9223/session")
            cdp_probe.assert_not_called()
            self.assertEqual(snapshot["capabilities"]["browser_remote"]["health"], "healthy")
            self.assertEqual(snapshot["capabilities"]["browser_bidi"]["health"], "healthy")
            profile = json.loads(
                (ROOKERY_ROOT / "adapters" / "ctfd_browser" / "profile.json").read_text(encoding="utf-8")
            )
            checks = startup_checks(
                root,
                {
                    "adapter": {"id": "ctfd_browser"},
                    "capabilities": profile["capabilities"],
                    "scoring": profile["scoring"],
                },
                adapter.scope,
                snapshot,
            )
            remote_check = next(check for check in checks if check["name"] == "browser_remote")
            self.assertTrue(remote_check["ok"])
