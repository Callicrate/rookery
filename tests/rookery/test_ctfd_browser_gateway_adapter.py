from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

# ruff: noqa: E402
from rookery.portable.browser_cdp_scoring import BrowserCdpScoringError
from rookery.portable import browser_cdp_scoring
from rookery.portable.cli import render_start_prompt
from rookery.portable.environment import BrowserGatewayReadiness, EnvironmentPolicyError
from rookery.portable.scoped_transport import ScopedTransportError


def _load_adapter_module():
    path = ROOKERY_ROOT / "adapters" / "ctfd_browser_gateway" / "adapter.py"
    spec = importlib.util.spec_from_file_location("test_ctfd_browser_gateway_adapter", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load CTFd browser gateway adapter")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(spec.name)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            sys.modules.pop(spec.name, None)
        else:
            sys.modules[spec.name] = previous
    return module


class _Channel:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _OwnedTarget:
    def __init__(self, binding) -> None:
        self.binding = binding
        self.account_document = {"success": True, "data": {"id": 42, "team_id": 13}}
        self.page = _Channel()
        self.closed = False
        self.disposed = False

    def close(self, target_id: str, _timeout_seconds: float) -> bool:
        self.closed = target_id == self.binding.target_id
        return self.closed

    def dispose(self) -> None:
        if not self.closed:
            self.close(self.binding.target_id, 2.0)
        self.disposed = True
        self.page.close()


class _Response:
    def __init__(self, status: int, document: object, *, url: str = "https://ctf.example/api/v1/challenges/attempt") -> None:
        self.status = status
        self.headers = {"Content-Type": "application/json"}
        self._body = json.dumps(document).encode("utf-8")
        self._url = url

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def read(self, _maximum: int | None = None) -> bytes:
        return self._body

    def geturl(self) -> str:
        return self._url


class CTFdBrowserGatewayAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = _load_adapter_module()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config = {
            "base_url": "https://ctf.example",
            "scoring_mode": "team",
            "expected_account_id": "42",
            "expected_team_id": "13",
            "csrf_page_path": "/challenges",
            "session_lease_seconds": 60,
            "timeout": 30,
            "max_response_bytes": 262_144,
        }
        self.scope = {
            "acknowledged": True,
            "generation": 1,
            "expires_at": "unknown",
            "allowed_hosts": ["ctf.example"],
            "allowed_cidrs": [],
            "allowed_ports": [443],
            "allowed_protocols": ["https"],
            "allowed_file_origins": [],
            "platform_hosts": ["ctf.example"],
            "max_attachment_bytes": 1024,
        }
        self.adapter = self.module.CTFdBrowserGatewayAdapter(
            self.root,
            {"adapter": {"id": "ctfd_browser_gateway", "config": self.config}},
            self.scope,
        )
        self.gateway = BrowserGatewayReadiness(
            boot_nonce="b" * 64,
            policy_sha256="a" * 64,
            expires_at="2099-01-01T00:00:00Z",
            proxy_port=9002,
            status_port=9003,
        )
        self.token = "token-fixture"
        self.token_transport = mock.Mock()
        self.token_transport_fingerprint = "c" * 64

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _read_result(self, request):
        if request.operation == "account":
            return SimpleNamespace(document={"success": True, "data": {"id": 42}}, text=None)
        if request.operation == "team":
            return SimpleNamespace(document={"success": True, "data": {"id": 13}}, text=None)
        if request.operation == "csrf":
            return SimpleNamespace(
                document=None,
                text='<script>var csrf_nonce = "fixture.csrf-nonce-123456";</script>',
            )
        if request.operation == "inventory":
            return SimpleNamespace(
                document={"success": True, "data": [{"id": 7, "name": "fixture"}]},
                text=None,
            )
        raise AssertionError(request.operation)

    def _gateway_identity(self, _url, _origin, *, boot_nonce=None):
        if boot_nonce not in {None, self.gateway.boot_nonce}:
            raise AssertionError(boot_nonce)
        return "https://ctf.example", self.gateway

    def _prepared_binding(self, _cdp_url, origin, gateway_policy):
        return self.module.BrowserScoringBinding(
            origin=origin,
            page_url="https://ctf.example/challenges",
            target_id="target-1",
            browser_context_id=None,
            frame_id="frame-1",
            execution_context_unique_id="isolated-world-1",
            gateway_policy_sha256=gateway_policy,
        )

    def _token_configuration(self):
        return self.token, self.token_transport, self.token_transport_fingerprint

    def _token_documents(self):
        return (
            {"success": True, "data": {"id": 42, "team_id": 13}},
            {"success": True, "data": {"id": 13}},
            {"success": True, "data": [{"id": 7, "name": "fixture"}]},
        )

    def _patch_preflight(self):
        counter = 0

        def counters(_gateway_url, _identity):
            nonlocal counter
            counter += 1
            return {"connected": 1, "bytes": counter}

        return mock.patch.multiple(
            self.adapter,
            _endpoints=mock.Mock(
                return_value=(
                    "http://127.0.0.1:9001",
                    "http://127.0.0.1:9003",
                    "https://ctf.example",
                )
            ),
            _gateway_identity=mock.Mock(side_effect=self._gateway_identity),
            _gateway_counters=mock.Mock(side_effect=counters),
            _token_configuration=mock.Mock(side_effect=self._token_configuration),
            _token_preflight=mock.Mock(
                side_effect=self.module._TokenReadAvailabilityError("account", "http_403")
            ),
        )

    def _patch_token_preflight(self):
        return mock.patch.multiple(
            self.adapter,
            _endpoints=mock.Mock(
                return_value=(
                    "http://127.0.0.1:9001",
                    "http://127.0.0.1:9003",
                    "https://ctf.example",
                )
            ),
            _gateway_identity=mock.Mock(side_effect=self._gateway_identity),
            _token_configuration=mock.Mock(side_effect=self._token_configuration),
        )

    def test_clean_bootstrap_derives_runtime_binding_and_never_attempts_a_post(self) -> None:
        self.assertFalse(
            {
                "page_url",
                "target_id",
                "browser_context_id",
                "frame_id",
                "execution_context_unique_id",
            }
            & set(self.config)
        )
        owned: list[_OwnedTarget] = []

        def open_owned(_cdp_url, origin, gateway_policy, _timeout):
            target = _OwnedTarget(self._prepared_binding(None, origin, gateway_policy))
            owned.append(target)
            return target

        def browser_read(_channel, request, *, close_owned_target):
            self.assertTrue(close_owned_target(request.binding.target_id, 2.0))
            return self._read_result(request)

        with (
            self._patch_preflight(),
            mock.patch.object(self.module, "verify_browser_cdp_endpoint"),
            mock.patch.object(self.module, "_open_owned_target", side_effect=open_owned),
            mock.patch.object(
                self.module,
                "execute_ctfd_browser_read",
                side_effect=browser_read,
            ) as reads,
            mock.patch.object(self.module, "execute_ctfd_browser_scoring") as scoring,
        ):
            snapshot = self.adapter.sync()

        self.assertEqual(snapshot["capabilities"]["scoring"]["health"], "degraded")
        self.assertEqual(
            [call.args[1].operation for call in reads.call_args_list], ["account", "team", "csrf", "inventory"]
        )
        scoring.assert_not_called()
        self.assertTrue(all(target.closed and target.disposed for target in owned))

    @unittest.skipUnless(os.name == "posix", "private execution evidence requires Linux/WSL")
    def test_token_identity_inventory_and_one_post_need_no_browser_after_preflight(self) -> None:
        token_get = mock.Mock(side_effect=self._token_documents())
        response = _Response(200, {"success": True, "data": {"correct": False}})
        with (
            self._patch_token_preflight(),
            mock.patch.object(self.module, "verify_browser_cdp_endpoint") as cdp,
            mock.patch.object(self.adapter, "_token_get", token_get),
            mock.patch.object(self.adapter, "_read") as browser_read,
            mock.patch.object(self.module, "_open_owned_target") as browser_target,
            mock.patch.object(self.module, "execute_ctfd_browser_scoring") as browser_scoring,
            mock.patch.object(self.module, "open_scoped_url", return_value=response) as token_post,
        ):
            snapshot = self.adapter.sync()
            self.assertEqual(snapshot["capabilities"]["scoring"]["health"], "healthy")
            self.assertEqual(
                [(call.kwargs["phase"], call.kwargs["path"]) for call in token_get.call_args_list],
                [
                    ("account", "/api/v1/users/me"),
                    ("team", "/api/v1/teams/me"),
                    ("inventory", "/api/v1/challenges"),
                ],
            )
            cdp.reset_mock()
            gateway_identity = self.adapter._gateway_identity
            gateway_identity.reset_mock()
            execution = self.adapter.execute_action(
                {"objective_id": "7", "exact_value": "flag{candidate}", "action_kind": "flag"},
                self.root / "evidence",
            )
            self.assertEqual(cdp.call_count, 0)
            gateway_identity.assert_not_called()

        self.assertEqual(execution["verdict"]["verdict"], "rejected")
        self.assertEqual(token_post.call_count, 1)
        request = token_post.call_args.args[1]
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.full_url, "https://ctf.example/api/v1/challenges/attempt")
        browser_read.assert_not_called()
        browser_target.assert_not_called()
        browser_scoring.assert_not_called()
        self.assertNotIn(self.token, (self.root / "evidence" / "request.json").read_text(encoding="utf-8"))

    def test_typed_token_read_availability_uses_browser_fallback(self) -> None:
        counter = 0

        def counters(_gateway_url, _gateway):
            nonlocal counter
            counter += 1
            return {"connected": 1, "bytes": counter}

        with (
            self._patch_token_preflight(),
            mock.patch.object(self.module, "verify_browser_cdp_endpoint"),
            mock.patch.object(
                self.adapter,
                "_token_preflight",
                side_effect=self.module._TokenReadAvailabilityError("account", "http_403"),
            ) as token_read,
            mock.patch.object(self.adapter, "_gateway_counters", side_effect=counters),
            mock.patch.object(
                self.adapter,
                "_read",
                side_effect=lambda _cdp, _origin, _policy, *, operation: self._read_result(
                    SimpleNamespace(operation=operation)
                ),
            ) as browser_read,
        ):
            snapshot = self.adapter.sync()

        self.assertEqual(snapshot["capabilities"]["scoring"]["health"], "degraded")
        self.assertEqual(
            snapshot["capabilities"]["scoring"]["detail"],
            "token_primary_unavailable; browser_fallback_ready",
        )
        token_read.assert_called_once()
        self.assertEqual(
            [call.kwargs["operation"] for call in browser_read.call_args_list],
            ["account", "team", "csrf", "inventory"],
        )

    @unittest.skipUnless(os.name == "posix", "private execution evidence requires Linux/WSL")
    def test_token_post_outcomes_do_not_retry_browser(self) -> None:
        nested: dict[str, object] = {}
        for _ in range(33):
            nested = {"nested": nested}
        cases = (
            ("timeout", TimeoutError("fixture timeout"), None, "ctfd_token_post_indeterminate"),
            ("forbidden", _Response(403, {"success": False, "data": {"message": "denied"}}), "auth_blocked", None),
            ("ambiguous", _Response(200, {"success": True, "data": {"message": "queued"}}), "unknown", None),
            ("partial", _Response(200, {"success": True, "data": {"status": "partial", "message": "solved"}}), "unknown", None),
            ("rate_limited", _Response(429, {"success": False, "data": {"status": "rate-limited", "message": "Not accepted"}}), "transport_error", None),
            ("nested", _Response(200, {"success": True, "data": nested}), None, "ctfd_token_post_response_invalid"),
        )
        for name, effect, expected_verdict, expected_error in cases:
            with self.subTest(name=name):
                token_get = mock.Mock(side_effect=self._token_documents())
                post_behavior = (
                    {"return_value": effect}
                    if isinstance(effect, _Response)
                    else {"side_effect": effect}
                )
                with (
                    self._patch_token_preflight(),
                    mock.patch.object(self.module, "verify_browser_cdp_endpoint") as cdp,
                    mock.patch.object(self.adapter, "_token_get", token_get),
                    mock.patch.object(self.adapter, "_read") as browser_read,
                    mock.patch.object(self.module, "_open_owned_target") as browser_target,
                    mock.patch.object(self.module, "execute_ctfd_browser_scoring") as browser_scoring,
                    mock.patch.object(self.module, "open_scoped_url", **post_behavior) as token_post,
                ):
                    self.assertEqual(self.adapter.sync()["capabilities"]["scoring"]["health"], "healthy")
                    cdp.reset_mock()
                    gateway_identity = self.adapter._gateway_identity
                    gateway_identity.reset_mock()
                    envelope = {"objective_id": "7", "exact_value": "flag{candidate}", "action_kind": "flag"}
                    if expected_error:
                        with self.assertRaisesRegex(RuntimeError, expected_error):
                            self.adapter.execute_action(envelope, self.root / name)
                    else:
                        execution = self.adapter.execute_action(envelope, self.root / name)
                        self.assertEqual(execution["verdict"]["verdict"], expected_verdict)
                    self.assertEqual(cdp.call_count, 0)
                    gateway_identity.assert_not_called()

                self.assertEqual(token_post.call_count, 1)
                browser_read.assert_not_called()
                browser_target.assert_not_called()
                browser_scoring.assert_not_called()
                if expected_error:
                    response = (self.root / name / "response.json").read_text(encoding="utf-8")
                    self.assertIn(expected_error, response)

    def test_token_preflight_json_depth_failure_is_terminal_without_browser_fallback(self) -> None:
        nested: dict[str, object] = {}
        for _ in range(33):
            nested = {"nested": nested}
        response = _Response(200, {"success": True, "data": nested}, url="https://ctf.example/api/v1/users/me")
        with (
            self._patch_token_preflight(),
            mock.patch.object(self.module, "verify_browser_cdp_endpoint"),
            mock.patch.object(self.module, "open_scoped_url", return_value=response),
            mock.patch.object(self.adapter, "_read") as browser_read,
        ):
            snapshot = self.adapter.sync()

        self.assertEqual(snapshot["challenges"], [])
        self.assertIn("ctfd_token_read_account_protocol_invalid", snapshot["capabilities"]["scoring"]["detail"])
        browser_read.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "private execution evidence requires Linux/WSL")
    def test_token_post_ctfd_statuses_are_determinate_scorer_truth(self) -> None:
        cases = (
            ("correct", "accepted"),
            ("incorrect", "rejected"),
            ("already_solved", "already-accepted"),
        )
        for status, expected in cases:
            with self.subTest(status=status):
                token_get = mock.Mock(side_effect=self._token_documents())
                response = _Response(200, {"success": True, "data": {"status": status, "message": "ignored"}})
                with (
                    self._patch_token_preflight(),
                    mock.patch.object(self.module, "verify_browser_cdp_endpoint"),
                    mock.patch.object(self.adapter, "_token_get", token_get),
                    mock.patch.object(self.module, "open_scoped_url", return_value=response),
                    mock.patch.object(self.module, "_open_owned_target") as browser_target,
                ):
                    self.assertEqual(self.adapter.sync()["capabilities"]["scoring"]["health"], "healthy")
                    execution = self.adapter.execute_action(
                        {"objective_id": "7", "exact_value": "flag{candidate}", "action_kind": "flag"},
                        self.root / f"token-{status}",
                    )

                self.assertEqual(execution["verdict"]["verdict"], expected)
                browser_target.assert_not_called()

    def test_browser_post_ctfd_statuses_require_exact_scorer_truth(self) -> None:
        action = browser_cdp_scoring.CTFdScoringAction(
            binding=self._prepared_binding(None, "https://ctf.example", "a" * 64),
            challenge_id=7,
            candidate="flag{candidate}",
            csrf_token="fixture.csrf-token-1234",
        )
        for status, expected in (
            ("correct", "accepted"),
            ("incorrect", "rejected"),
            ("already_solved", "already-accepted"),
        ):
            with self.subTest(status=status), mock.patch.object(
                browser_cdp_scoring,
                "_execute_browser_request",
                return_value=SimpleNamespace(
                    status=200,
                    headers={},
                    body=json.dumps({"success": True, "data": {"status": status, "message": "ignored"}}).encode("utf-8"),
                ),
            ):
                result = browser_cdp_scoring.execute_ctfd_browser_scoring(
                    _Channel(),
                    action,
                    close_owned_target=lambda _target_id, _timeout: True,
                )
                self.assertEqual(result.verdict["verdict"], expected)
        for status, http_status, message in (
            ("partial", 200, "solved"),
            ("ratelimited", 429, "Not accepted"),
        ):
            with self.subTest(status=status), mock.patch.object(
                browser_cdp_scoring,
                "_execute_browser_request",
                return_value=SimpleNamespace(
                    status=http_status,
                    headers={},
                    body=json.dumps({"success": True, "data": {"status": status, "message": message}}).encode("utf-8"),
                ),
            ):
                result = browser_cdp_scoring.execute_ctfd_browser_scoring(
                    _Channel(),
                    action,
                    close_owned_target=lambda _target_id, _timeout: True,
                )
                self.assertEqual(result.verdict["scorer_truth"], "unknown")

    @unittest.skipUnless(os.name == "posix", "private execution evidence requires Linux/WSL")
    def test_browser_partial_response_is_retained_for_indeterminate_handoff(self) -> None:
        binding = self._prepared_binding(None, "https://ctf.example", "a" * 64)
        owned = _OwnedTarget(binding)
        lease = self.module._SessionLease(
            transport="browser_gateway",
            origin="https://ctf.example",
            scope_sha256="scope" * 16,
            gateway_boot_nonce=self.gateway.boot_nonce,
            gateway_policy_sha256=self.gateway.policy_sha256,
            gateway_expires_at=self.gateway.expires_at,
            account_id="42",
            team_id="13",
            csrf_token="fixture.csrf-token-1234",
            expires_at=10_000_000.0,
        )
        response = SimpleNamespace(
            status=200,
            headers={},
            body=b'{"success":true,"data":{"status":"partial","message":"solved"}}',
        )
        counters = iter(({"connected": 1, "bytes": 1}, {"connected": 1, "bytes": 2}))
        with (
            mock.patch.object(self.adapter, "_gateway_counters", side_effect=lambda *_args: next(counters)),
            mock.patch.object(self.module, "_open_owned_target", return_value=owned),
            mock.patch.object(
                browser_cdp_scoring,
                "_execute_browser_request",
                return_value=response,
            ),
            mock.patch.object(
                self.module,
                "execute_ctfd_browser_scoring",
                wraps=browser_cdp_scoring.execute_ctfd_browser_scoring,
            ),
        ):
            result = self.adapter._browser_submission(
                lease,
                "http://127.0.0.1:9001",
                "http://127.0.0.1:9003",
                "https://ctf.example",
                self.gateway,
                7,
                "flag{candidate}",
                self.root / "browser-indeterminate",
            )

        self.assertEqual(result["verdict"]["verdict"], "unknown")
        saved = (self.root / "browser-indeterminate" / "response.json").read_text(encoding="utf-8")
        self.assertIn("partial", saved)
        self.assertIn("solved", saved)
        self.assertTrue(owned.closed and owned.disposed)

    def test_token_identity_mismatch_is_terminal_without_browser_fallback(self) -> None:
        with (
            self._patch_token_preflight(),
            mock.patch.object(self.module, "verify_browser_cdp_endpoint"),
            mock.patch.object(
                self.adapter,
                "_token_get",
                return_value={"success": True, "data": {"id": 99}},
            ),
            mock.patch.object(self.adapter, "_read") as browser_read,
            mock.patch.object(self.module, "_open_owned_target") as browser_target,
        ):
            snapshot = self.adapter.sync()

        self.assertEqual(snapshot["challenges"], [])
        self.assertIn("ctfd_token_identity_mismatch", snapshot["capabilities"]["scoring"]["detail"])
        browser_read.assert_not_called()
        browser_target.assert_not_called()

    def test_missing_token_blocks_after_gateway_preflight_without_browser_fallback(self) -> None:
        with (
            self._patch_token_preflight(),
            mock.patch.object(self.module, "verify_browser_cdp_endpoint") as cdp,
            mock.patch.object(
                self.adapter,
                "_token_configuration",
                side_effect=RuntimeError("ctfd_token_configuration_invalid"),
            ),
            mock.patch.object(self.adapter, "_token_get") as token_get,
            mock.patch.object(self.adapter, "_read") as browser_read,
        ):
            snapshot = self.adapter.sync()

        self.assertEqual(snapshot["challenges"], [])
        self.assertIn("ctfd_token_configuration_invalid", snapshot["capabilities"]["scoring"]["detail"])
        cdp.assert_called_once()
        token_get.assert_not_called()
        browser_read.assert_not_called()

    def test_token_path_still_requires_cdp_and_gateway_readiness(self) -> None:
        with (
            self._patch_token_preflight(),
            mock.patch.object(
                self.module,
                "verify_browser_cdp_endpoint",
                side_effect=EnvironmentPolicyError("browser_cdp_unreachable"),
            ),
            mock.patch.object(self.adapter, "_token_get") as token_get,
            mock.patch.object(self.adapter, "_gateway_identity") as gateway_identity,
        ):
            snapshot = self.adapter.sync()

        self.assertEqual(snapshot["challenges"], [])
        self.assertIn("browser_cdp_unreachable", snapshot["capabilities"]["scoring"]["detail"])
        token_get.assert_not_called()
        gateway_identity.assert_not_called()

    def test_token_redirect_classification_is_narrow(self) -> None:
        login = _Response(
            200,
            {"success": True, "data": {}},
            url="https://ctf.example/login?next=/api/v1/challenges",
        )
        canonical = _Response(
            200,
            {"success": True, "data": []},
            url="https://ctf.example/challenges",
        )
        with self.assertRaisesRegex(self.module._TokenReadAvailabilityError, "access_redirect"):
            self.adapter._token_document(
                login,
                phase="inventory",
                origin="https://ctf.example",
                requested_url="https://ctf.example/api/v1/challenges",
            )
        with self.assertRaisesRegex(RuntimeError, "redirect_unrecognized"):
            self.adapter._token_document(
                canonical,
                phase="inventory",
                origin="https://ctf.example",
                requested_url="https://ctf.example/api/v1/challenges",
            )

    def test_cross_origin_403_is_terminal_without_browser_fallback(self) -> None:
        cross_origin = _Response(
            403,
            {"success": False, "data": {"message": "denied"}},
            url="https://support.example/login",
        )
        with (
            self._patch_token_preflight(),
            mock.patch.object(self.module, "verify_browser_cdp_endpoint"),
            mock.patch.object(self.module, "open_scoped_url", return_value=cross_origin),
            mock.patch.object(self.adapter, "_read") as browser_read,
        ):
            snapshot = self.adapter.sync()

        self.assertEqual(snapshot["challenges"], [])
        self.assertIn("redirect_origin_invalid", snapshot["capabilities"]["scoring"]["detail"])
        browser_read.assert_not_called()

    def test_scoped_transport_route_reasons_are_narrowly_classified(self) -> None:
        with mock.patch.object(
            self.module,
            "open_scoped_url",
            side_effect=ScopedTransportError("scoped_dns_resolution_failed"),
        ):
            with self.assertRaisesRegex(self.module._TokenReadAvailabilityError, "route_unavailable"):
                self.adapter._token_get(
                    "https://ctf.example",
                    self.token,
                    self.token_transport,
                    path="/api/v1/users/me",
                    phase="account",
                )
        with mock.patch.object(
            self.module,
            "open_scoped_url",
            side_effect=ScopedTransportError("scoped_http_request_failed"),
        ):
            with self.assertRaisesRegex(self.module._TokenReadAvailabilityError, "route_unavailable"):
                self.adapter._token_get(
                    "https://ctf.example",
                    self.token,
                    self.token_transport,
                    path="/api/v1/users/me",
                    phase="account",
                )
        with mock.patch.object(
            self.module,
            "open_scoped_url",
            side_effect=ScopedTransportError("scoped_tls_verification_failed"),
        ):
            with self.assertRaisesRegex(RuntimeError, "transport_invalid"):
                self.adapter._token_get(
                    "https://ctf.example",
                    self.token,
                    self.token_transport,
                    path="/api/v1/users/me",
                    phase="account",
                )

    def test_profile_declares_flag_and_no_submit_evidence_modes(self) -> None:
        profile = json.loads(
            (ROOKERY_ROOT / "adapters" / "ctfd_browser_gateway" / "profile.json").read_text(encoding="utf-8")
        )
        self.assertEqual(profile["scoring"]["completion_mode"], "scorer_truth")
        self.assertEqual(profile["scoring"]["action_kinds"], ["flag", "no_submit_evidence"])

    def test_gateway_mismatch_blocks_sync_without_browser_access(self) -> None:
        with (
            mock.patch.object(self.adapter, "_endpoints", return_value=("cdp", "gateway", "https://ctf.example")),
            mock.patch.object(self.module, "verify_browser_cdp_endpoint"),
            mock.patch.object(
                self.adapter,
                "_gateway_identity",
                side_effect=EnvironmentPolicyError("browser_gateway_policy_mismatch"),
            ),
            mock.patch.object(self.adapter, "_read") as read,
        ):
            snapshot = self.adapter.sync()

        read.assert_not_called()
        self.assertEqual(snapshot["challenges"], [])
        self.assertIn("browser_gateway_policy_mismatch", snapshot["capabilities"]["scoring"]["detail"])

    def test_start_prompt_requires_the_selected_gateway_review_chain(self) -> None:
        path = render_start_prompt(
            self.root,
            {
                "identity": {"name": "fixture"},
                "profile": "ctfd_browser_gateway",
                "adapter": {"id": "ctfd_browser_gateway"},
            },
            SimpleNamespace(unresolved_required=[]),
            {"tools": []},
        )
        text = path.read_text(encoding="utf-8")

        self.assertIn("token-first normalized reads and reviewed scoring", text)
        self.assertIn("internal fallback only after a typed read-only availability failure", text)
        self.assertIn("proposal, independent review, bounded authorization, sealed-plan execution", text)
        self.assertIn("never a raw-CDP or manual scoring route", text)

    def test_sync_requires_a_gateway_byte_delta_from_the_typed_account_read(self) -> None:
        with (
            self._patch_preflight(),
            mock.patch.object(self.module, "verify_browser_cdp_endpoint"),
            mock.patch.object(
                self.adapter,
                "_gateway_counters",
                return_value={"connected": 1, "bytes": 100},
            ),
            mock.patch.object(
                self.adapter,
                "_read",
                side_effect=lambda _cdp, _origin, _policy, *, operation: self._read_result(
                    SimpleNamespace(operation=operation)
                ),
            ) as reads,
        ):
            snapshot = self.adapter.sync()

        self.assertEqual(snapshot["challenges"], [])
        self.assertIn(
            "browser_context_proxy_unverified",
            snapshot["capabilities"]["scoring"]["detail"],
        )
        self.assertEqual([call.kwargs["operation"] for call in reads.call_args_list], ["account"])

    def test_malformed_csrf_path_closes_the_owned_target_before_read_dispatch(self) -> None:
        owned = _OwnedTarget(self._prepared_binding(None, "https://ctf.example", "a" * 64))
        self.adapter.config["csrf_page_path"] = "/a//b"
        with mock.patch.object(self.module, "_open_owned_target", return_value=owned):
            with self.assertRaisesRegex(RuntimeError, "csrf_page_path is invalid"):
                self.adapter._read(
                    "http://127.0.0.1:9001",
                    "https://ctf.example",
                    "a" * 64,
                    operation="inventory",
                )

        self.assertTrue(owned.closed and owned.disposed)

    def test_target_account_and_team_mismatches_fail_closed(self) -> None:
        cases = (
            (
                "target",
                BrowserCdpScoringError("browser_target_binding_mismatch", committed=False),
                "browser_target_binding_mismatch",
            ),
            (
                "account",
                SimpleNamespace(document={"success": True, "data": {"id": 99}}, text=None),
                "expected account",
            ),
            (
                "team",
                SimpleNamespace(document={"success": True, "data": {"id": 99}}, text=None),
                "expected team",
            ),
        )
        for name, value, expected in cases:
            with self.subTest(name=name):
                adapter = self.module.CTFdBrowserGatewayAdapter(
                    self.root,
                    {"adapter": {"id": "ctfd_browser_gateway", "config": dict(self.config)}},
                    {},
                )
                values = iter(
                    (
                        value,
                        self._read_result(SimpleNamespace(operation="team")),
                        self._read_result(SimpleNamespace(operation="csrf")),
                        self._read_result(SimpleNamespace(operation="inventory")),
                    )
                    if name == "account"
                    else (
                        self._read_result(SimpleNamespace(operation="account")),
                        value,
                        self._read_result(SimpleNamespace(operation="csrf")),
                        self._read_result(SimpleNamespace(operation="inventory")),
                    )
                    if name == "team"
                    else (value,)
                )
                counter = 0

                def counters(_gateway_url, _identity):
                    nonlocal counter
                    counter += 1
                    return {"connected": 1, "bytes": counter}

                def read(_cdp_url, _origin, _policy, *, operation):
                    item = next(values)
                    if isinstance(item, BaseException):
                        raise item
                    return item

                with (
                    mock.patch.object(adapter, "_endpoints", return_value=("cdp", "gateway", "https://ctf.example")),
                    mock.patch.object(adapter, "_gateway_identity", side_effect=self._gateway_identity),
                    mock.patch.object(adapter, "_gateway_counters", side_effect=counters),
                    mock.patch.object(adapter, "_token_configuration", side_effect=self._token_configuration),
                    mock.patch.object(
                        adapter,
                        "_token_preflight",
                        side_effect=self.module._TokenReadAvailabilityError("account", "http_403"),
                    ),
                    mock.patch.object(self.module, "verify_browser_cdp_endpoint"),
                    mock.patch.object(adapter, "_read", side_effect=read),
                ):
                    snapshot = adapter.sync()
                self.assertEqual(snapshot["challenges"], [])
                self.assertIn(expected, snapshot["capabilities"]["scoring"]["detail"])

    @unittest.skipUnless(os.name == "posix", "private execution evidence requires Linux/WSL")
    def test_incorrect_2xx_is_rejected_and_second_direct_call_cannot_post_again(self) -> None:
        owned = _OwnedTarget(self._prepared_binding(None, "https://ctf.example", "a" * 64))
        result = SimpleNamespace(
            response={"http_status": 200, "headers": {}, "data": {"success": True, "data": {"correct": False}}},
            verdict={"verdict": "rejected", "scorer_truth": "rejected", "transport_truth": "success"},
        )
        with (
            self._patch_preflight(),
            mock.patch.object(self.module, "verify_browser_cdp_endpoint"),
            mock.patch.object(
                self.adapter,
                "_read",
                side_effect=lambda _cdp, _origin, _policy, *, operation: self._read_result(
                    SimpleNamespace(operation=operation)
                ),
            ),
            mock.patch.object(self.module, "_open_owned_target", return_value=owned),
            mock.patch.object(self.module, "execute_ctfd_browser_scoring", return_value=result) as scoring,
        ):
            self.assertEqual(self.adapter.sync()["capabilities"]["scoring"]["health"], "degraded")
            execution = self.adapter.execute_action(
                {"objective_id": "7", "exact_value": "flag{candidate}", "action_kind": "flag"},
                self.root / "evidence",
            )
            with self.assertRaisesRegex(RuntimeError, "lease is unavailable"):
                self.adapter.execute_action(
                    {"objective_id": "7", "exact_value": "flag{candidate}", "action_kind": "flag"},
                    self.root / "evidence",
                )

        self.assertEqual(execution["verdict"]["verdict"], "rejected")
        self.assertEqual(scoring.call_count, 1)
        self.assertIs(scoring.call_args.kwargs["close_owned_target"].__self__, owned)
        self.assertTrue(owned.disposed)
        request = (self.root / "evidence" / "request.json").read_text(encoding="utf-8")
        response = (self.root / "evidence" / "response.json").read_text(encoding="utf-8")
        self.assertIn("flag{candidate}", request)
        self.assertNotIn("9001", request + response)
        self.assertNotIn("fixture.csrf-nonce", request + response)

    @unittest.skipUnless(os.name == "posix", "private execution evidence requires Linux/WSL")
    def test_cloudflare_html_or_cdp_loss_after_release_propagates_indeterminate_error(self) -> None:
        owned = _OwnedTarget(self._prepared_binding(None, "https://ctf.example", "a" * 64))
        committed = BrowserCdpScoringError("browser_scorer_response_invalid", committed=True)
        with (
            self._patch_preflight(),
            mock.patch.object(self.module, "verify_browser_cdp_endpoint"),
            mock.patch.object(
                self.adapter,
                "_read",
                side_effect=lambda _cdp, _origin, _policy, *, operation: self._read_result(
                    SimpleNamespace(operation=operation)
                ),
            ),
            mock.patch.object(self.module, "_open_owned_target", return_value=owned),
            mock.patch.object(self.module, "execute_ctfd_browser_scoring", side_effect=committed),
        ):
            self.adapter.sync()
            with self.assertRaises(BrowserCdpScoringError) as caught:
                self.adapter.execute_action(
                    {"objective_id": "7", "exact_value": "flag{candidate}", "action_kind": "flag"},
                    self.root / "evidence",
                )

        self.assertTrue(caught.exception.committed)
        self.assertEqual(caught.exception.outcome, "indeterminate")

    @unittest.skipUnless(os.name == "posix", "private execution evidence requires Linux/WSL")
    def test_fresh_bootstrap_account_swap_blocks_before_post(self) -> None:
        owned = _OwnedTarget(self._prepared_binding(None, "https://ctf.example", "a" * 64))
        owned.account_document = {"success": True, "data": {"id": 99}}
        with (
            self._patch_preflight(),
            mock.patch.object(self.module, "verify_browser_cdp_endpoint"),
            mock.patch.object(
                self.adapter,
                "_read",
                side_effect=lambda _cdp, _origin, _policy, *, operation: self._read_result(
                    SimpleNamespace(operation=operation)
                ),
            ),
            mock.patch.object(self.module, "_open_owned_target", return_value=owned),
            mock.patch.object(self.module, "execute_ctfd_browser_scoring") as scoring,
        ):
            self.assertEqual(self.adapter.sync()["capabilities"]["scoring"]["health"], "degraded")
            with self.assertRaisesRegex(RuntimeError, "account changed since preflight"):
                self.adapter.execute_action(
                    {"objective_id": "7", "exact_value": "flag{candidate}", "action_kind": "flag"},
                    self.root / "evidence",
                )
            with self.assertRaisesRegex(RuntimeError, "lease is unavailable"):
                self.adapter.execute_action(
                    {"objective_id": "7", "exact_value": "flag{candidate}", "action_kind": "flag"},
                    self.root / "evidence",
                )

        scoring.assert_not_called()
        self.assertTrue(owned.closed and owned.disposed)

    @unittest.skipUnless(os.name == "posix", "private execution evidence requires Linux/WSL")
    def test_fresh_bootstrap_same_account_team_swap_blocks_before_post(self) -> None:
        owned = _OwnedTarget(self._prepared_binding(None, "https://ctf.example", "a" * 64))
        owned.account_document = {"success": True, "data": {"id": 42, "team_id": 99}}
        with (
            self._patch_preflight(),
            mock.patch.object(self.module, "verify_browser_cdp_endpoint"),
            mock.patch.object(
                self.adapter,
                "_read",
                side_effect=lambda _cdp, _origin, _policy, *, operation: self._read_result(
                    SimpleNamespace(operation=operation)
                ),
            ),
            mock.patch.object(self.module, "_open_owned_target", return_value=owned),
            mock.patch.object(self.module, "execute_ctfd_browser_scoring") as scoring,
        ):
            self.assertEqual(self.adapter.sync()["capabilities"]["scoring"]["health"], "degraded")
            with self.assertRaisesRegex(RuntimeError, "team changed since preflight"):
                self.adapter.execute_action(
                    {"objective_id": "7", "exact_value": "flag{candidate}", "action_kind": "flag"},
                    self.root / "evidence",
                )
            with self.assertRaisesRegex(RuntimeError, "lease is unavailable"):
                self.adapter.execute_action(
                    {"objective_id": "7", "exact_value": "flag{candidate}", "action_kind": "flag"},
                    self.root / "evidence",
                )

        scoring.assert_not_called()
        self.assertTrue(owned.closed and owned.disposed)

    @unittest.skipUnless(os.name == "posix", "private execution evidence requires Linux/WSL")
    def test_fresh_bootstrap_missing_team_blocks_before_post(self) -> None:
        owned = _OwnedTarget(self._prepared_binding(None, "https://ctf.example", "a" * 64))
        owned.account_document = {"success": True, "data": {"id": 42}}
        with (
            self._patch_preflight(),
            mock.patch.object(self.module, "verify_browser_cdp_endpoint"),
            mock.patch.object(
                self.adapter,
                "_read",
                side_effect=lambda _cdp, _origin, _policy, *, operation: self._read_result(
                    SimpleNamespace(operation=operation)
                ),
            ),
            mock.patch.object(self.module, "_open_owned_target", return_value=owned),
            mock.patch.object(self.module, "execute_ctfd_browser_scoring") as scoring,
        ):
            self.assertEqual(self.adapter.sync()["capabilities"]["scoring"]["health"], "degraded")
            with self.assertRaisesRegex(RuntimeError, "invalid CTFd account team response"):
                self.adapter.execute_action(
                    {"objective_id": "7", "exact_value": "flag{candidate}", "action_kind": "flag"},
                    self.root / "evidence",
                )
            with self.assertRaisesRegex(RuntimeError, "lease is unavailable"):
                self.adapter.execute_action(
                    {"objective_id": "7", "exact_value": "flag{candidate}", "action_kind": "flag"},
                    self.root / "evidence",
                )

        scoring.assert_not_called()
        self.assertTrue(owned.closed and owned.disposed)

    @unittest.skipUnless(os.name == "posix", "private execution evidence requires Linux/WSL")
    def test_user_mode_does_not_require_a_fresh_team_identity(self) -> None:
        self.config["scoring_mode"] = "user"
        self.config.pop("expected_team_id")
        owned = _OwnedTarget(self._prepared_binding(None, "https://ctf.example", "a" * 64))
        owned.account_document = {"success": True, "data": {"id": 42}}
        result = SimpleNamespace(
            response={"http_status": 200, "headers": {}, "data": {"success": True}},
            verdict={"verdict": "accepted", "scorer_truth": "accepted", "transport_truth": "success"},
        )
        with (
            self._patch_preflight(),
            mock.patch.object(self.module, "verify_browser_cdp_endpoint"),
            mock.patch.object(
                self.adapter,
                "_read",
                side_effect=lambda _cdp, _origin, _policy, *, operation: self._read_result(
                    SimpleNamespace(operation=operation)
                ),
            ) as reads,
            mock.patch.object(self.module, "_open_owned_target", return_value=owned),
            mock.patch.object(self.module, "execute_ctfd_browser_scoring", return_value=result) as scoring,
        ):
            self.assertEqual(self.adapter.sync()["capabilities"]["scoring"]["health"], "degraded")
            execution = self.adapter.execute_action(
                {"objective_id": "7", "exact_value": "flag{candidate}", "action_kind": "flag"},
                self.root / "evidence",
            )

        self.assertEqual(execution["verdict"]["verdict"], "accepted")
        self.assertEqual([call.kwargs["operation"] for call in reads.call_args_list], ["account", "csrf", "inventory"])
        scoring.assert_called_once()
        self.assertTrue(owned.closed and owned.disposed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
