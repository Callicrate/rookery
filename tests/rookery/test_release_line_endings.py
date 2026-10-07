from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from tests.rookery.env_fixtures import configure_event_environment
from tests.rookery.test_preparation_and_isolation import copy_rookery

os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.validator import validate_tree  # noqa: E402


class ReleaseLineEndingTests(unittest.TestCase):
    def test_shell_consumed_release_files_require_lf(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            copy_rookery(root)
            configure_event_environment(root, "manual")
            clean = validate_tree(root, strict_release=True)
            self.assertTrue(clean["ok"], clean)

            environment = root / ".env"
            environment.write_bytes(environment.read_bytes().replace(b"\n", b"\r\n"))
            invalid = validate_tree(root, strict_release=True)

            self.assertFalse(invalid["ok"])
            self.assertIn(
                "CRLF line endings in shell-consumed release file: .env",
                invalid["errors"],
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
