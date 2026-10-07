from __future__ import annotations

import hashlib
import os
import re
import tempfile
import unittest
from pathlib import Path

from tests.rookery.support import ROOKERY_ROOT
from tests.rookery.test_preparation_and_isolation import copy_rookery

os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

SOURCE_VERSION = (ROOKERY_ROOT / "VERSION").read_text(encoding="utf-8").strip()


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


class UpgradeHandoffTests(unittest.TestCase):
    def test_rejected_file_level_state_recovery_is_not_shipped(self) -> None:
        for relative in (
            "bin/state-recovery",
            "lib/rookery/portable/recovery.py",
        ):
            self.assertFalse(
                (ROOKERY_ROOT / relative).exists(),
                f"independently rejected recovery surface was shipped: {relative}",
            )

    def test_documented_contract_is_side_by_side_and_fail_closed(self) -> None:
        text = (ROOKERY_ROOT / "docs/upgrade.md").read_text(encoding="utf-8")

        for required in (
            "rookery-$VERSION.zip",
            "rookery-$VERSION.zip.sha256",
            "rookery-$VERSION.manifest.json",
            "never overlay",
            "import runtime state into new source",
            "Rollback is selection of a complete",
            "Linux home",
            "private POSIX modes",
        ):
            self.assertIn(required.casefold(), text.casefold())

    def test_release_docs_use_version_variables_and_explain_artifact_trust(self) -> None:
        docs = {
            path: (ROOKERY_ROOT / path).read_text(encoding="utf-8")
            for path in ("README.md", "docs/upgrade.md")
        }
        for path, text in docs.items():
            self.assertIn("$VERSION", text, path)
            self.assertNotRegex(text, r"dist/rookery-", path)
            self.assertNotRegex(text, r"rookery-\d{4}\.\d{2}\.\d{2}", path)

            shell = "\n".join(
                re.findall(
                    r"```(?:bash|sh)\s*\n(.*?)```",
                    text,
                    flags=re.DOTALL | re.IGNORECASE,
                )
            )
            self.assertNotRegex(shell, r"rookery-\d{4}\.\d{2}\.\d{2}")

        upgrade = docs["docs/upgrade.md"]
        for artifact in (
            "rookery-$VERSION.zip",
            "rookery-$VERSION.zip.sha256",
            "rookery-$VERSION.manifest.json",
        ):
            self.assertIn(artifact, upgrade)

        normalized_readme = re.sub(r"\s+", " ", docs["README.md"]).casefold()
        normalized_upgrade = re.sub(r"\s+", " ", upgrade).casefold()
        self.assertIn("local content integrity", normalized_readme)
        self.assertIn("do not authenticate the publisher", normalized_readme)
        self.assertIn("local integrity", normalized_upgrade)
        self.assertIn("do not authenticate a publisher", normalized_upgrade)

    def test_receiver_docs_use_trusted_bounded_extraction_before_candidate_code(self) -> None:
        readme = (ROOKERY_ROOT / "README.md").read_text(encoding="utf-8")
        upgrade = (ROOKERY_ROOT / "docs/upgrade.md").read_text(encoding="utf-8")
        normalized_readme = re.sub(r"\s+", " ", readme).casefold()
        normalized_upgrade = re.sub(r"\s+", " ", upgrade).casefold()

        self.assertIn("./bin/rookery validate --release --source-checkout", readme)
        self.assertIn("./bin/build-release --output-dir", readme)

        shell_blocks = re.findall(
            r"```(?:bash|sh)\s*\n(.*?)```",
            upgrade,
            flags=re.DOTALL | re.IGNORECASE,
        )
        self.assertTrue(shell_blocks, "no receiver shell workflow found in docs/upgrade.md")
        self.assertNotRegex(
            "\n".join(shell_blocks),
            r"(?m)^\s*unzip(?:\s|$)",
            "raw unzip command documented in docs/upgrade.md",
        )
        for required in (
            '"$TRUSTED_RECEIVER/bin/build-release"',
            "--extract-archive",
            "--manifest",
            "--extract-dir",
            "test ! -e",
        ):
            self.assertIn(required, upgrade, f"missing bounded receiver contract: {required}")
        self.assertLess(
            upgrade.index('"$TRUSTED_RECEIVER/bin/build-release"'),
            upgrade.index("./bin/rookery validate --release"),
            "candidate validation precedes trusted extraction",
        )

        for required in (
            "local content integrity",
            "do not authenticate the publisher",
            "source trust comes from the operator's chosen trusted channel",
        ):
            self.assertIn(required.casefold(), normalized_readme)

        for required in (
            "local integrity",
            "do not authenticate a publisher",
            "separately trusted channel",
            "do not execute `bin/build-release` from the candidate archive",
        ):
            self.assertIn(required.casefold(), normalized_upgrade)

    def test_side_by_side_staging_cannot_change_preserved_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            old = base / "rookery-old"
            old.mkdir()
            (old / ".env").write_text("TOKEN=dummy-old-value\n", encoding="utf-8")
            (old / "event.json").write_text('{"id":"old"}\n', encoding="utf-8")
            state = old / "state"
            state.mkdir()
            (state / "events.sqlite3").write_bytes(b"preserved-old-state")
            before = tree_digest(old)

            staged = base / f"rookery-{SOURCE_VERSION}-install" / "rookery"
            copy_rookery(staged)
            (staged / ".env").write_text("PLATFORM_ADAPTER=manual\n", encoding="utf-8")

            self.assertEqual(tree_digest(old), before)
            self.assertFalse((staged / "state").exists())
            self.assertEqual((old / "state/events.sqlite3").read_bytes(), b"preserved-old-state")


if __name__ == "__main__":
    unittest.main(verbosity=2)
