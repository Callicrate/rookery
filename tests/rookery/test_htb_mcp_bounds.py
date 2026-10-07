from __future__ import annotations

# ruff: noqa: E402

import json
import runpy
import sys
import unittest

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

from rookery.portable.adapters import CommandAdapter
from rookery.portable.registry import load_registry, select_entries


class HtbMcpRemovalTests(unittest.TestCase):
    def test_shipped_htb_tree_has_no_remote_mcp_or_bearer_surface(self) -> None:
        adapter_root = ROOKERY_ROOT / "adapters" / "htb"
        descriptor = json.loads(
            (adapter_root / "adapter.json").read_text(encoding="utf-8")
        )

        self.assertNotIn("codex_config", descriptor)
        self.assertNotIn("tools", descriptor)
        for removed in (
            "codex.toml",
            "tools.json",
            "bin/htb-mcp-proxy",
            "bin/htb-mcp-doctor",
            "agents/ctf_htb_mcp_platform_scout.toml",
        ):
            self.assertFalse((adapter_root / removed).exists(), removed)

        shipped_paths = [
            path
            for path in adapter_root.rglob("*")
            if path.is_file() and not path.is_symlink()
        ]
        source = "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in shipped_paths
        ).lower()
        names = "\n".join(
            path.relative_to(adapter_root).as_posix() for path in shipped_paths
        ).lower()
        for forbidden in (
            "mcp.hackthebox.ai",
            "htb-mcp",
            "htb_mcp",
            "api_access_token",
            "bearer",
            "scout",
            "mcp",
        ):
            self.assertNotIn(forbidden, source)
            self.assertNotIn(forbidden, names)

        example = (adapter_root / "env.example").read_text(encoding="utf-8")
        self.assertIn("ADAPTER_CONFIG_INVENTORY_ARGV=", example)
        self.assertIn("ADAPTER_CONFIG_SUBMIT_ARGV=", example)
        self.assertIn("ADAPTER_CONFIG_INVENTORY_ENV_KEYS=[]", example)
        self.assertIn("ADAPTER_CONFIG_SUBMIT_ENV_KEYS=[]", example)

    def test_selected_registry_includes_the_sherlock_evidence_role(self) -> None:
        namespace = runpy.run_path(
            str(ROOKERY_ROOT / "adapters" / "htb" / "adapter.py")
        )
        self.assertIs(namespace["HTBAdapter"].__bases__[0], CommandAdapter)

        manifest = {
            "adapter": {"id": "htb"},
            "surface": {"bundles": ["adapter:htb"], "categories": []},
            "capabilities": {"required": [], "optional": []},
        }
        active_agents = select_entries(
            load_registry(ROOKERY_ROOT, "agents", manifest), manifest
        )
        htb_agent_ids = {
            str(entry["id"])
            for entry in active_agents
            if str(entry.get("id", "")).startswith("ctf_htb_")
        }
        self.assertEqual(
            htb_agent_ids,
            {
                "ctf_htb_machine_operator",
                "ctf_htb_scaled_event_prioritizer",
                "ctf_htb_sherlock_analyst",
            },
        )

        active_tools = select_entries(
            load_registry(ROOKERY_ROOT, "tools", manifest), manifest
        )
        registry_text = json.dumps(
            {"agents": active_agents, "tools": active_tools}, sort_keys=True
        ).lower()
        for forbidden in (
            "mcp.hackthebox.ai",
            "htb-mcp",
            "htb_mcp",
            "api_access_token",
            "bearer",
            "scout",
        ):
            self.assertNotIn(forbidden, registry_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
