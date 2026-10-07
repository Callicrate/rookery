from __future__ import annotations

# ruff: noqa: E402

import sys
import tempfile
import unittest
from pathlib import Path

LIB = Path(__file__).resolve().parents[2] / "rookery" / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

from rookery.portable import environment, util


class UtilEnvironmentCompatibilityTests(unittest.TestCase):
    def test_legacy_complete_environment_helpers_are_removed(self):
        """No utility compatibility path may reconstruct an ambient mapping."""

        self.assertFalse(hasattr(util, "load_environment"))
        self.assertFalse(hasattr(util, "parse_env_file"))

    def test_central_declared_reader_remains_importable_with_util(self):
        """The central reader works without a util-to-environment import cycle."""

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / ".env").write_text(
                "DECLARED=literal-value\nUNDECLARED=must-not-be-returned\n",
                encoding="utf-8",
            )
            resolved = environment.read_declared_environment(
                root,
                (environment.EnvKey("DECLARED", environment.EnvClass.ROOKERY_CONFIG),),
                parent={},
            )

        self.assertEqual(dict(resolved.values), {"DECLARED": "literal-value"})
        self.assertNotIn("UNDECLARED", resolved.values)


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
