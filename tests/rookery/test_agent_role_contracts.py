from __future__ import annotations

import json
import tomllib
import unittest

from tests.rookery.support import ROOKERY_ROOT


class AgentRoleContractTests(unittest.TestCase):
    def test_persona_and_overlay_authoring_system_is_not_shipped(self) -> None:
        self.assertFalse((ROOKERY_ROOT / "souls").exists())
        self.assertFalse((ROOKERY_ROOT / "docs/persona_map.md").exists())
        self.assertFalse((ROOKERY_ROOT / "docs/agents_and_personas.md").exists())
        self.assertTrue((ROOKERY_ROOT / "docs/agents.md").is_file())

        agent_files = list((ROOKERY_ROOT / "agents/catalog").glob("*.toml"))
        agent_files.extend((ROOKERY_ROOT / "adapters").glob("*/agents/*.toml"))
        agent_files.extend((ROOKERY_ROOT / "extensions").glob("*/agents/*.toml"))
        self.assertGreater(len(agent_files), 70)
        for path in agent_files:
            with self.subTest(path=path.relative_to(ROOKERY_ROOT)):
                text = path.read_text(encoding="utf-8")
                parsed = tomllib.loads(text)
                instructions = str(parsed.get("developer_instructions") or "")
                self.assertIn("## Role mission", instructions)
                self.assertNotIn("## Persona foundation", instructions)
                self.assertNotIn("## SWE-swarm overlay lens", instructions)
                self.assertNotIn("one overlay per agent keeps diversity crisp", instructions)

    def test_htb_sherlock_role_has_distinct_evidence_contract(self) -> None:
        registry = json.loads(
            (ROOKERY_ROOT / "adapters/htb/agents.json").read_text(encoding="utf-8")
        )
        row = next(
            entry for entry in registry if entry["id"] == "ctf_htb_sherlock_analyst"
        )
        self.assertEqual(row["requires_any"], ["adapter:htb"])
        self.assertIn("question-indexed", row["admission"]["capability_gap"])

        source = ROOKERY_ROOT / row["source"]
        agent = tomllib.loads(source.read_text(encoding="utf-8"))
        instructions = agent["developer_instructions"]
        for required in (
            "question ledger",
            "source hashes",
            "distinguishes observed facts from hypotheses",
            "do not submit",
            "Never invent missing event facts",
        ):
            self.assertIn(required, instructions)


if __name__ == "__main__":
    unittest.main(verbosity=2)
