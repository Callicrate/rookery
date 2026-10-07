from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ROOKERY = ROOT / "rookery"


class OperatorClaimTruthDocsTests(unittest.TestCase):
    def test_release_docs_use_version_variables_without_claiming_current_artifacts(self) -> None:
        docs = {
            relative_path: (ROOKERY / relative_path).read_text(encoding="utf-8")
            for relative_path in ("README.md", "docs/upgrade.md")
        }

        for relative_path, text in docs.items():
            with self.subTest(path=relative_path):
                self.assertIn("$VERSION", text)
                self.assertNotRegex(text, r"dist/rookery-")
                self.assertNotRegex(text, r"rookery-\d{4}\.\d{2}\.\d{2}")

        upgrade = docs["docs/upgrade.md"]
        for artifact in (
            "rookery-$VERSION.zip",
            "rookery-$VERSION.zip.sha256",
            "rookery-$VERSION.manifest.json",
        ):
            self.assertIn(artifact, upgrade)

        normalized_readme = " ".join(docs["README.md"].split()).casefold()
        normalized_upgrade = " ".join(upgrade.split()).casefold()
        self.assertIn("local content integrity", normalized_readme)
        self.assertIn("do not authenticate the publisher", normalized_readme)
        self.assertIn("local integrity", normalized_upgrade)
        self.assertIn("do not authenticate a publisher", normalized_upgrade)

    def test_browser_selector_is_explicitly_reserved_and_inert(self) -> None:
        template = (ROOKERY / ".env.example").read_text(encoding="utf-8")
        self.assertIn(
            "Reserved and inert in this release: browser capture is unreachable",
            template,
        )
        self.assertIn("no browser-capture metadata is produced", template)
        self.assertIn("BROWSER_ENV_KEYS=[]", template)

        playq = (ROOKERY / "bin/playq").read_text(encoding="utf-8")
        self.assertIn('"browser_network_scope_unenforced:', playq)
        self.assertNotIn("browser_environment", playq)
        self.assertNotIn("run_bounded_argv", playq)
        self.assertNotIn("write_bytes", playq)

    def test_named_vpn_aliases_are_documented_as_refusal_shims(self) -> None:
        vpn_doc = (ROOKERY / "docs/network_vpn.md").read_text(encoding="utf-8")
        self.assertIn(
            "No functioning Rookery-managed VPN commands exist in this release.",
            vpn_doc,
        )
        self.assertIn("refusal shims", vpn_doc)

        aliases = {
            "vpn-status": "status",
            "vpn-health": "health",
            "vpn-connect": "ensure",
            "vpn-reconnect": "restart",
        }
        for alias, action in aliases.items():
            with self.subTest(alias=alias):
                self.assertIn(f"`bin/{alias}`", vpn_doc)
                wrapper = (ROOKERY / "bin" / alias).read_text(encoding="utf-8")
                self.assertIn(f'/vpn" {action} "$@"', wrapper)

        vpn_shim = (ROOKERY / "bin/vpn").read_text(encoding="utf-8")
        self.assertIn('REFUSAL = "vpn_privileged_supervision_unavailable"', vpn_shim)
        self.assertIn("print(REFUSAL, file=sys.stderr)\n    return 2", vpn_shim)


if __name__ == "__main__":
    unittest.main()
