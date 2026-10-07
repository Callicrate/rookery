# ruff: noqa: E402, RUF100

from __future__ import annotations

import importlib
import os
import socket
import stat
import sys
import tempfile
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Self
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

from rookery.portable import adapters
from rookery.portable import scope as scope_module
from rookery.portable.adapters import capture_file, normalize_challenge
from rookery.portable.scope import open_scoped_url


def scoped(**changes: object) -> dict:
    scope = {
        "acknowledged": True,
        "generation": 7,
        "expires_at": "unknown",
        "allowed_hosts": ["allowed.test"],
        "allowed_cidrs": [],
        "allowed_ports": [],
        "allowed_protocols": ["http", "https"],
        "allowed_file_origins": [
            "downloads/*",
            "source.bin",
            "http://allowed.test/*",
        ],
        "platform_hosts": [],
        "max_attachment_bytes": 4096,
    }
    scope.update(changes)
    return scope


class FakeResponse:
    def __init__(
        self,
        status: int,
        *,
        location: str | None = None,
        data: bytes = b"",
    ) -> None:
        self.status = status
        self.headers = {} if location is None else {"Location": location}
        self._data = data
        self._offset = 0
        self.closed = False

    def getcode(self) -> int:
        return self.status

    def geturl(self) -> str:
        return "http://allowed.test/fixture"

    def read(self, maximum: int = -1) -> bytes:
        if maximum < 0:
            maximum = len(self._data) - self._offset
        start = self._offset
        self._offset = min(len(self._data), start + maximum)
        return self._data[start : self._offset]

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        del args
        self.close()


def FakeOpener(responses: list[FakeResponse]) -> object:
    return scope_module._EndpointAwareTestTransport(responses)


class ScopedHttpTests(unittest.TestCase):
    def test_default_opener_never_connects_to_an_ambient_proxy(self) -> None:
        target_requests: list[str] = []
        proxy_requests: list[str] = []

        class TargetHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                target_requests.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"target")

            def log_message(self, _format: str, *args: object) -> None:
                del args

        class ProxyHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                proxy_requests.append(self.path)
                self.send_response(502)
                self.end_headers()

            def log_message(self, _format: str, *args: object) -> None:
                del args

        target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
        proxy = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        target_thread.start()
        proxy_thread.start()

        proxy_url = f"http://127.0.0.1:{proxy.server_port}"
        proxy_environment = {
            "HTTP_PROXY": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "ALL_PROXY": proxy_url,
            "http_proxy": proxy_url,
            "https_proxy": proxy_url,
            "all_proxy": proxy_url,
            "NO_PROXY": "",
            "no_proxy": "",
        }
        original_getaddrinfo = socket.getaddrinfo

        def resolve_allowed_host(
            host: str,
            port: int,
            *args: object,
            **kwargs: object,
        ) -> object:
            if host == "allowed.test":
                return original_getaddrinfo("127.0.0.1", port, *args, **kwargs)
            return original_getaddrinfo(host, port, *args, **kwargs)

        try:
            with (
                mock.patch.dict(os.environ, proxy_environment, clear=False),
                mock.patch("socket.getaddrinfo", side_effect=resolve_allowed_host),
            ):
                reloaded_scope = importlib.reload(scope_module)
                with reloaded_scope.open_scoped_url(
                    scoped(
                        allowed_ports=[target.server_port],
                        allowed_cidrs=["127.0.0.1/32"],
                    ),
                    f"http://allowed.test:{target.server_port}/direct",
                ) as response:
                    self.assertEqual(response.read(), b"target")
        finally:
            importlib.reload(scope_module)
            target.shutdown()
            proxy.shutdown()
            target_thread.join(timeout=1)
            proxy_thread.join(timeout=1)
            target.server_close()
            proxy.server_close()

        self.assertEqual(target_requests, ["/direct"])
        self.assertEqual(proxy_requests, [])

    def test_generic_opener_is_not_a_scoped_transport_escape(self) -> None:
        with self.assertRaises(TypeError):
            open_scoped_url(scoped(), "http://allowed.test", transport=object())
        opener = urllib.request.build_opener()
        with mock.patch("socket.getaddrinfo") as resolver, self.assertRaises(TypeError):
            open_scoped_url(
                scoped(), "http://allowed.test", transport=opener
            )
        resolver.assert_not_called()

    def test_offscope_redirect_makes_no_second_request(self) -> None:
        redirect = FakeResponse(302, location="http://outside.test/private")
        opener = FakeOpener([redirect])

        with self.assertRaisesRegex(RuntimeError, "redirect blocked by scope"):
            open_scoped_url(
                scoped(),
                "http://allowed.test/start",
                _test_transport=opener,
            )

        self.assertEqual(len(opener.requests), 1)
        self.assertTrue(redirect.closed)

    def test_allowed_redirects_are_bounded(self) -> None:
        responses = [
            FakeResponse(302, location="/loop"),
            FakeResponse(302, location="/loop"),
            FakeResponse(302, location="/loop"),
        ]
        opener = FakeOpener(responses)

        with self.assertRaisesRegex(RuntimeError, "redirect limit exceeded"):
            open_scoped_url(
                scoped(),
                "http://allowed.test/start",
                _test_transport=opener,
                max_redirects=2,
            )

        self.assertEqual(len(opener.requests), 3)
        self.assertTrue(all(response.closed for response in responses))

    def test_allowed_redirect_reaches_scoped_target(self) -> None:
        opener = FakeOpener(
            [
                FakeResponse(302, location="/target"),
                FakeResponse(200, data=b"target"),
            ]
        )

        with open_scoped_url(
            scoped(),
            "http://allowed.test/start",
            _test_transport=opener,
        ) as response:
            self.assertEqual(response.read(), b"target")

        self.assertEqual(
            [request.full_url for request in opener.requests],
            ["http://allowed.test/start", "http://allowed.test/target"],
        )

    def test_https_downgrade_makes_no_second_request(self) -> None:
        opener = FakeOpener(
            [FakeResponse(302, location="http://allowed.test/plaintext")]
        )

        with self.assertRaisesRegex(RuntimeError, "downgrade"):
            open_scoped_url(
                scoped(allowed_file_origins=["https://allowed.test/*"]),
                "https://allowed.test/start",
                _test_transport=opener,
            )

        self.assertEqual(len(opener.requests), 1)

    def test_credentialed_url_is_rejected_before_request(self) -> None:
        opener = FakeOpener([])

        with self.assertRaisesRegex(RuntimeError, "credentialed"):
            open_scoped_url(
                scoped(),
                "http://user:password@allowed.test/private",
                _test_transport=opener,
            )

        self.assertEqual(opener.requests, [])

    def test_cross_origin_redirect_drops_credentials(self) -> None:
        opener = FakeOpener(
            [
                FakeResponse(302, location="http://second.test/final"),
                FakeResponse(200, data=b"ok"),
            ]
        )
        request = urllib.request.Request(
            "http://allowed.test/start",
            headers={
                "Authorization": "Bearer secret",
                "Cookie": "session=secret",
                "Mcp-Session-Id": "session-secret",
                "X-Api-Key": "api-secret",
                "Accept": "application/json",
            },
        )

        response = open_scoped_url(
            scoped(allowed_hosts=["allowed.test", "second.test"]),
            request,
            _test_transport=opener,
        )
        response.close()

        redirected_headers = {
            name.casefold(): value for name, value in opener.requests[1].header_items()
        }
        self.assertNotIn("authorization", redirected_headers)
        self.assertNotIn("cookie", redirected_headers)
        self.assertNotIn("mcp-session-id", redirected_headers)
        self.assertNotIn("x-api-key", redirected_headers)
        self.assertEqual(redirected_headers["accept"], "application/json")

    def test_post_redirect_is_rejected_without_second_request(self) -> None:
        opener = FakeOpener([FakeResponse(302, location="/other")])
        request = urllib.request.Request(
            "http://allowed.test/start",
            data=b"{}",
            method="POST",
        )

        with self.assertRaisesRegex(RuntimeError, "non-idempotent"):
            open_scoped_url(scoped(), request, _test_transport=opener)

        self.assertEqual(len(opener.requests), 1)


class LocalAttachmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_traversal_absolute_and_backslash_origins_are_rejected(self) -> None:
        (self.root / "downloads").mkdir()
        (self.root / ".env").write_bytes(b"secret")
        origins = [
            "downloads/../.env",
            (self.root / ".env").as_posix(),
            "downloads\\secret.bin",
        ]

        for index, origin in enumerate(origins):
            with self.subTest(origin=origin):
                destination = self.root / f"captured-{index}.bin"
                with self.assertRaises(RuntimeError):
                    capture_file(
                        self.root,
                        scoped(),
                        {"path": origin},
                        destination,
                    )
                self.assertFalse(destination.exists())

    def test_symlink_source_is_rejected_before_read(self) -> None:
        source = self.root / "source.bin"
        target = self.root / "target.bin"
        target.write_bytes(b"target")
        try:
            source.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")

        with self.assertRaisesRegex(RuntimeError, "symlink"):
            capture_file(
                self.root,
                scoped(),
                {"path": "source.bin"},
                self.root / "captured.bin",
            )

    def test_broken_symlink_source_is_rejected_before_read(self) -> None:
        source = self.root / "source.bin"
        try:
            source.symlink_to(self.root / "missing.bin")
        except OSError as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")

        with self.assertRaisesRegex(RuntimeError, "broken"):
            capture_file(
                self.root,
                scoped(),
                {"path": "source.bin"},
                self.root / "captured.bin",
            )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO creation requires POSIX")
    def test_fifo_source_is_rejected_before_read(self) -> None:
        fifo = self.root / "source.bin"
        os.mkfifo(fifo)

        with self.assertRaisesRegex(RuntimeError, "regular file"):
            capture_file(
                self.root,
                scoped(),
                {"path": "source.bin"},
                self.root / "captured.bin",
            )

    def test_source_identity_change_is_rejected(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"stable bytes")
        descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        info = os.fstat(descriptor)
        stable_identity = adapters._source_identity(info)
        changed_identity = (
            stable_identity[0],
            stable_identity[1],
            stable_identity[2],
            stable_identity[3] + 1,
        )

        try:
            with (
                mock.patch.object(adapters, "ensure_private_dir"),
                mock.patch.object(adapters, "ensure_private_file"),
                mock.patch.object(
                    adapters,
                    "_open_local_descriptor",
                    return_value=descriptor,
                ),
                mock.patch.object(
                    adapters,
                    "_source_identity",
                    side_effect=[stable_identity, changed_identity],
                ),
                self.assertRaisesRegex(RuntimeError, "changed while"),
            ):
                capture_file(
                    self.root,
                    scoped(),
                    {"path": "source.bin"},
                    self.root / "captured.bin",
                )
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass
        self.assertFalse((self.root / "captured.bin").exists())

    def test_duplicate_target_preserves_first_capture(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"first")
        destination = self.root / "captured.bin"
        with (
            mock.patch.object(adapters, "ensure_private_dir"),
            mock.patch.object(adapters, "ensure_private_file"),
            mock.patch.object(adapters, "_verify_fallback_destination_parent"),
            mock.patch.object(adapters, "_verify_fallback_publication"),
        ):
            result = capture_file(
                self.root,
                scoped(),
                {"path": "source.bin"},
                destination,
            )
        source.write_bytes(b"second")

        with (
            mock.patch.object(adapters, "ensure_private_dir"),
            mock.patch.object(adapters, "ensure_private_file"),
            mock.patch.object(adapters, "_verify_fallback_destination_parent"),
            mock.patch.object(adapters, "_verify_fallback_publication"),
            self.assertRaisesRegex(RuntimeError, "already exists"),
        ):
            capture_file(
                self.root,
                scoped(),
                {"path": "source.bin"},
                destination,
            )

        self.assertEqual(destination.read_bytes(), b"first")
        self.assertEqual(result["scope_generation"], 7)
        self.assertFalse(result["reused_existing"])
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)

    @unittest.skipUnless(os.name == "posix", "private capture requires POSIX modes")
    def test_identical_existing_destination_is_reused(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"stable capture")
        for label, descriptor_walk in (("descriptor", True), ("fallback", False)):
            with self.subTest(publication=label):
                destination = self.root / f"captured-{label}.bin"
                with mock.patch.object(
                    adapters,
                    "_descriptor_walk_supported",
                    return_value=descriptor_walk,
                ):
                    first = capture_file(
                        self.root,
                        scoped(),
                        {"path": "source.bin"},
                        destination,
                    )
                    second = capture_file(
                        self.root,
                        scoped(),
                        {"path": "source.bin"},
                        destination,
                    )

                self.assertFalse(first["reused_existing"])
                self.assertTrue(second["reused_existing"])
                self.assertEqual(second["sha256"], first["sha256"])
                self.assertEqual(destination.read_bytes(), b"stable capture")

    @unittest.skipUnless(os.name == "posix", "private capture requires POSIX modes")
    def test_concurrent_identical_captures_reuse_one_destination(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"concurrent capture")
        destination = self.root / "captured.bin"
        barrier = threading.Barrier(2)
        results: list[dict] = []
        failures: list[BaseException] = []
        result_lock = threading.Lock()

        def capture() -> None:
            try:
                barrier.wait(timeout=5)
                result = capture_file(
                    self.root,
                    scoped(),
                    {"path": "source.bin"},
                    destination,
                )
                with result_lock:
                    results.append(result)
            except BaseException as exc:  # pragma: no cover - reported below
                with result_lock:
                    failures.append(exc)

        workers = [threading.Thread(target=capture) for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=10)

        self.assertFalse(any(worker.is_alive() for worker in workers))
        self.assertEqual(failures, [])
        self.assertEqual(len(results), 2)
        self.assertEqual(
            sorted(result["reused_existing"] for result in results),
            [False, True],
        )
        self.assertEqual(destination.read_bytes(), b"concurrent capture")

    @unittest.skipUnless(os.name == "posix", "private capture requires POSIX modes")
    def test_destination_symlink_is_not_reused(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"captured bytes")
        target = self.root / "target.bin"
        target.write_bytes(b"sentinel")
        destination = self.root / "captured.bin"
        try:
            destination.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")

        with self.assertRaisesRegex(RuntimeError, "already exists.*private regular"):
            capture_file(
                self.root,
                scoped(),
                {"path": "source.bin"},
                destination,
            )

        self.assertEqual(target.read_bytes(), b"sentinel")

    def test_destination_must_stay_below_workspace(self) -> None:
        (self.root / "source.bin").write_bytes(b"data")
        outside = self.root.parent / f"{self.root.name}-outside.bin"
        self.addCleanup(outside.unlink, missing_ok=True)

        with self.assertRaisesRegex(RuntimeError, "escapes the workspace"):
            capture_file(
                self.root,
                scoped(),
                {"path": "source.bin"},
                outside,
            )
        self.assertFalse(outside.exists())

    def test_http_body_is_streamed_under_attachment_bound(self) -> None:
        response = FakeResponse(200, data=b"x" * 4097)
        destination = self.root / "captured.bin"

        with (
            mock.patch.object(adapters, "ensure_private_dir"),
            mock.patch.object(
                adapters,
                "open_scoped_url",
                return_value=response,
            ),
            self.assertRaisesRegex(RuntimeError, "exceeds declared byte bound"),
        ):
            capture_file(
                self.root,
                scoped(),
                {"url": "http://allowed.test/file.bin"},
                destination,
            )

        self.assertTrue(response.closed)
        self.assertFalse(destination.exists())


class ChallengeNormalizationTests(unittest.TestCase):
    def test_optional_challenge_state_fields_are_preserved_when_bounded(self) -> None:
        normalized = normalize_challenge(
            {
                "id": "fixture",
                "hidden": False,
                "solvable": True,
                "submittable": False,
                "platform_submittable": True,
                "submission_mode": "multiple_choice",
            }
        )

        self.assertEqual(
            {
                field: normalized[field]
                for field in (
                    "hidden",
                    "solvable",
                    "submittable",
                    "platform_submittable",
                    "submission_mode",
                )
            },
            {
                "hidden": False,
                "solvable": True,
                "submittable": False,
                "platform_submittable": True,
                "submission_mode": "multiple_choice",
            },
        )
        self.assertFalse(
            any(
                field in normalize_challenge({"id": "legacy"})
                for field in (
                    "hidden",
                    "solvable",
                    "submittable",
                    "platform_submittable",
                    "submission_mode",
                )
            )
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
