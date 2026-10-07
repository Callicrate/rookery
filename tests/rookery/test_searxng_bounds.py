from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.test_preparation_and_isolation import copy_rookery
from rookery.portable.scope import CompiledScopeBinding


class SearxngBoundTests(unittest.TestCase):
    def test_response_is_bounded_before_json_parse(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        copy_rookery(root)
        (root / ".env").write_text(
            "SEARXNG_MODE=auto\nSEARXNG_URL=https://fixture.invalid/search\n",
            encoding="utf-8",
        )
        (root / "state").mkdir(exist_ok=True)
        (root / "state" / "scope.json").write_text(
            '{"acknowledged":true,"generation":1,"expires_at":"unknown",'
            '"allowed_hosts":["fixture.invalid"],"allowed_cidrs":[],'
            '"allowed_ports":[443],"allowed_protocols":["https"],'
            '"allowed_file_origins":[],"platform_hosts":[],'
            '"max_attachment_bytes":1024}',
            encoding="utf-8",
        )
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b"x" * 1025
        namespace = runpy.run_path(
            str(root / "bin/searxng"), run_name="searxng_bounds_test"
        )
        scope = {
            "acknowledged": True,
            "generation": 1,
            "expires_at": "unknown",
            "allowed_hosts": ["fixture.invalid"],
            "allowed_cidrs": [],
            "allowed_ports": [443],
            "allowed_protocols": ["https"],
            "allowed_file_origins": [],
            "platform_hosts": [],
            "max_attachment_bytes": 1024,
        }
        binding = CompiledScopeBinding(
            scope=scope,
            scope_generation=1,
            stop_generation=0,
            file_sha256="a" * 64,
            content_sha256="b" * 64,
            launch_binding_sha256="c" * 64,
        )
        transport = mock.Mock(return_value=response)

        with (
            mock.patch.dict(
                namespace["query"].__globals__,
                {
                    "open_scoped_url": transport,
                    "load_canonical_compiled_scope": lambda _root: binding,
                    "verify_canonical_compiled_scope_binding": lambda _root, **_kwargs: binding,
                },
            ),
            self.assertRaisesRegex(RuntimeError, "exceeds configured byte limit"),
        ):
            namespace["query"](
                root, ["fixture", "--max-response-bytes", "1024"]
            )

        response.read.assert_called_once_with(1025)
        self.assertEqual(transport.call_count, 1)
        temporary.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
