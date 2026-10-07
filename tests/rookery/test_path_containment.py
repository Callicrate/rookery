from __future__ import annotations

# ruff: noqa: E402

import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Callable
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable import cli, outcomes, writeups
from rookery.portable.owned_paths import objective_storage_component
from rookery.portable.util import path_component_id


class RecordingStore:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.events: list[tuple[str, dict[str, object]]] = []
        self.harvested_reports: dict[str, dict[str, object]] = {}
        self.connection = sqlite3.connect(":memory:")
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);"
            "CREATE TABLE events ("
            "seq INTEGER PRIMARY KEY AUTOINCREMENT, "
            "event_id TEXT, event_type TEXT, created_at TEXT, "
            "generation INTEGER, actor TEXT, payload_json TEXT);"
        )

    def transaction(self, callback: Callable[[sqlite3.Connection], object]) -> object:
        result = callback(self.connection)
        self.connection.commit()
        return result

    def insert_in_transaction(
        self,
        connection: sqlite3.Connection,
        event_type: str,
        payload: dict[str, object],
        *,
        actor: str,
        generation: int,
    ) -> None:
        connection.execute(
            "INSERT INTO events (event_id,event_type,created_at,generation,actor,payload_json) "
            "VALUES (?,?,?,?,?,?)",
            (
                "fixture-event",
                event_type,
                "fixture-time",
                generation,
                actor,
                json.dumps(payload),
            ),
        )
        self.events.append((event_type, payload))
        if event_type == "report.harvested":
            self.harvested_reports[str(payload["report_path"])] = payload

    def append(self, event_type: str, payload: dict[str, object], **_: object) -> None:
        self.events.append((event_type, payload))
        if event_type == "report.harvested":
            self.harvested_reports[str(payload["report_path"])] = payload

    def rebuild(self) -> dict[str, object]:
        return {"current": {"harvested_reports": self.harvested_reports}}


def _write_json(path: Path, payload: object, mode: int | None = None) -> None:
    del mode
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _write_text(path: Path, text: str, mode: int | None = None) -> None:
    del mode
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _ensure_file(path: Path) -> None:
    if path.is_symlink():
        raise OSError(f"refusing symlinked file: {path}")
    if not path.exists():
        path.touch()


class PathContainmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.store = RecordingStore(self.root)
        self.addCleanup(self.store.connection.close)
        completion = mock.patch.object(
            writeups,
            "resolve_canonical_completion",
            side_effect=lambda _store, *, objective_id, plan_id: {
                "state": "accepted",
                "objective_id": objective_id,
                "plan_id": plan_id,
                "scorer_evidence": "submissions/response.json",
            },
        )
        completion.start()
        self.addCleanup(completion.stop)
        self.writeup_patches = [
            mock.patch.object(writeups, "atomic_write_json", side_effect=_write_json),
            mock.patch.object(writeups, "atomic_write_text", side_effect=_write_text),
            mock.patch.object(
                writeups, "ensure_private_dir", side_effect=_ensure_directory
            ),
            mock.patch.object(
                writeups, "ensure_private_file", side_effect=_ensure_file
            ),
        ]
        for patch in self.writeup_patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.addCleanup(self.temporary_directory.cleanup)

    def _capsule(self, objective_id: str, action_reference: str = "proposal:one"):
        return writeups.create_capsule(
            self.store,
            self.root,
            objective_id=objective_id,
            action_reference=action_reference,
            scorer_evidence="submissions/response.json",
            reproduction_path="exploit/solve.py",
            material_provenance=["analysis/lane/REPORT.md"],
            dead_path_checkpoint="none",
        )

    def test_component_validator_rejects_portability_and_collision_hazards(self):
        invalid = {
            "empty": "",
            "dot": ".",
            "traversal": "..",
            "posix-absolute": "/tmp/escape",
            "windows-absolute": "C:\\escape",
            "slash": "nested/child",
            "backslash": "nested\\child",
            "nul": "name\x00suffix",
            "control": "name\x1fsuffix",
            "unicode-nfc": "caf\u00e9",
            "unicode-nfd": "cafe\u0301",
            "upper-case-collision": "Case",
            "reserved-device": "con",
            "reserved-device-extension": "com1.txt",
            "trailing-dot": "name.",
            "trailing-space": "name ",
            "overlong": "a" * 129,
        }
        for label, value in invalid.items():
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    path_component_id(value)
        self.assertEqual(path_component_id("challenge-42.v1"), "challenge-42.v1")
        self.assertEqual(path_component_id("a" * 128), "a" * 128)

    def test_external_objective_ids_use_opaque_storage_without_rewriting_identity(self):
        external = [
            "../escape",
            "/tmp/escape",
            "C:\\escape",
            "nested/child",
            "nested\\child",
            "caf\u00e9",
            "Case",
            "nul",
            "a" * 129,
        ]
        for objective_id in external:
            with self.subTest(objective_id=repr(objective_id)):
                component = objective_storage_component(objective_id)
                self.assertTrue(component.startswith("challenge-"))
                self.assertEqual(component, objective_storage_component(objective_id))
                writeups.create_writeup(self.root, objective_id, "External")
                capsule = self._capsule(objective_id)
                self.assertEqual(capsule["objective_id"], objective_id)
                self.assertTrue((self.root / "writeups" / component).is_dir())
        for invalid in ("", "name\x00suffix", "name\x1fsuffix", "a" * 4097):
            with self.subTest(invalid=repr(invalid)):
                before_tree = list(self.root.rglob("*"))
                before_events = list(self.store.events)
                with self.assertRaises(ValueError):
                    writeups.create_writeup(self.root, invalid, "Unsafe")
                with self.assertRaises(ValueError):
                    self._capsule(invalid)
                self.assertEqual(before_tree, list(self.root.rglob("*")))
                self.assertEqual(before_events, self.store.events)

    def test_capsule_creation_is_idempotent_and_conflicts_preserve_evidence(self):
        first = self._capsule("challenge-42")
        capsule = (
            self.root
            / "writeups"
            / objective_storage_component("challenge-42")
            / "CAPSULE.json"
        )
        original_bytes = capsule.read_bytes()
        second = self._capsule("challenge-42")
        self.assertEqual(first, second)
        self.assertEqual(capsule.read_bytes(), original_bytes)
        self.assertEqual([event for event, _ in self.store.events], ["solve.capsule"])

        with self.assertRaisesRegex(ValueError, "different canonical payload"):
            self._capsule("challenge-42", action_reference="proposal:two")
        self.assertEqual(capsule.read_bytes(), original_bytes)
        self.assertEqual([event for event, _ in self.store.events], ["solve.capsule"])

    def test_symlinked_writeup_parent_and_final_file_are_refused(self):
        outside = self.root / "outside"
        outside.mkdir()
        external_capsule = outside / "CAPSULE.json"
        external_capsule.write_text("external capsule", encoding="utf-8")
        parent = self.root / "writeups"
        parent.mkdir()
        component = objective_storage_component("safe")
        try:
            (parent / component).symlink_to(outside, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"symlink support unavailable: {exc}")
        with self.assertRaises(ValueError):
            self._capsule("safe")
        self.assertEqual(external_capsule.read_text(encoding="utf-8"), "external capsule")
        self.assertEqual(self.store.events, [])

        (parent / component).unlink()
        safe = parent / component
        safe.mkdir()
        (safe / "CAPSULE.json").symlink_to(external_capsule)
        with self.assertRaises(ValueError):
            self._capsule("safe")
        self.assertEqual(external_capsule.read_text(encoding="utf-8"), "external capsule")
        self.assertEqual(self.store.events, [])

    def test_harvest_requires_bounded_analysis_relative_regular_file(self):
        report = self.root / "analysis/lane/REPORT.md"
        report.parent.mkdir(parents=True)
        report.write_text("report\n", encoding="utf-8")
        first = outcomes.harvest_report(self.store, self.root, "analysis/lane/REPORT.md")
        second = outcomes.harvest_report(self.store, self.root, "analysis/lane/REPORT.md")
        self.assertTrue(second["idempotent"])
        self.assertEqual(first["sha256"], second["sha256"])
        self.assertEqual([event for event, _ in self.store.events], ["report.harvested"])

        external = self.root / "outside.md"
        external.write_text("external", encoding="utf-8")
        with mock.patch.object(outcomes, "_bounded_report_sha256") as hash_report:
            with self.assertRaises(ValueError):
                outcomes.harvest_report(self.store, self.root, str(external))
        hash_report.assert_not_called()

        for report_path in [
            "../outside.md",
            "/tmp/outside.md",
            "C:\\outside.md",
            "analysis/../outside.md",
            "analysis\\lane\\REPORT.md",
            "reports/lane/REPORT.md",
        ]:
            with self.subTest(report_path=report_path):
                with self.assertRaises(ValueError):
                    outcomes.harvest_report(self.store, self.root, report_path)
        with mock.patch.object(outcomes, "MAX_HARVEST_REPORT_BYTES", 8):
            report.write_bytes(b"012345678")
            with self.assertRaisesRegex(ValueError, "byte limit"):
                outcomes.harvest_report(self.store, self.root, "analysis/lane/REPORT.md")
        self.assertEqual([event for event, _ in self.store.events], ["report.harvested"])

    def test_harvest_rejects_symlinked_parent_and_final_file(self):
        outside = self.root / "outside-report"
        outside.mkdir()
        external = outside / "REPORT.md"
        external.write_text("external", encoding="utf-8")
        analysis = self.root / "analysis"
        analysis.mkdir()
        try:
            (analysis / "linked").symlink_to(outside, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"symlink support unavailable: {exc}")
        with self.assertRaises(ValueError):
            outcomes.harvest_report(self.store, self.root, "analysis/linked/REPORT.md")
        self.assertEqual(self.store.events, [])

        (analysis / "linked").unlink()
        lane = analysis / "lane"
        lane.mkdir()
        (lane / "REPORT.md").symlink_to(external)
        with self.assertRaises(ValueError):
            outcomes.harvest_report(self.store, self.root, "analysis/lane/REPORT.md")
        self.assertEqual(external.read_text(encoding="utf-8"), "external")
        self.assertEqual(self.store.events, [])

    def test_cli_hashes_external_challenge_id_before_context_or_path_access(self):
        args = SimpleNamespace(platform_action="ingest", challenge_id="../escape")
        with (
            mock.patch.object(cli, "workspace_root", return_value=self.root),
            mock.patch.object(
                cli, "load_context", side_effect=RuntimeError("context reached")
            ) as load_context,
        ):
            with self.assertRaisesRegex(RuntimeError, "context reached"):
                cli.cmd_platform(args)
        load_context.assert_called_once_with(self.root, require_ready=True)
        self.assertEqual(list(self.root.rglob("*")), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
