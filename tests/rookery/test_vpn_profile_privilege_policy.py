from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rookery.portable.registry import render_surface
from tests.rookery.test_preparation_and_isolation import copy_rookery


class VpnRetirementSurfaceTests(unittest.TestCase):
    def test_vpn_tools_and_steward_are_not_selectable_for_a_vpn_capability(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_rookery(root)
            tools = json.loads((root / "registry" / "tools.json").read_text(encoding="utf-8"))
            agents = json.loads((root / "registry" / "agents.json").read_text(encoding="utf-8"))
            self.assertFalse(any(str(entry.get("id", "")).startswith("vpn") for entry in tools))
            self.assertNotIn("ctf_vpn_steward", {entry["id"] for entry in agents})

            inventory = render_surface(
                root,
                {
                    "profile": "vpn-required-fixture",
                    "adapter": {"id": "manual"},
                    "capabilities": {"required": ["vpn"]},
                    "surface": {"bundles": [], "categories": [], "extensions": []},
                },
            )
            self.assertFalse(any("vpn" in entry["id"] for entry in inventory["tools"]))
            self.assertFalse(any("vpn" in entry["id"] for entry in inventory["agents"]))
            active = (root / "ACTIVE_SURFACE.md").read_text(encoding="utf-8").lower()
            self.assertNotIn("bin/vpn", active)
            self.assertNotIn("ctf_vpn_steward", active)

    def test_operator_documentation_requires_external_supervision(self) -> None:
        text = (Path(__file__).resolve().parents[2] / "rookery" / "docs" / "network_vpn.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("externally supervised", text)
        self.assertIn("`state/vpn` material as authority", text)
        self.assertIn("operator remains responsible", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
