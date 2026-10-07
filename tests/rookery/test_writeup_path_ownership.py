import os
import sys
import tempfile
import unittest
from hashlib import sha256
import json
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.util import canonical_json, ensure_private_dir  # noqa: E402
from rookery.portable.owned_paths import (  # noqa: E402
    OPAQUE_IDENTIFIER_MAX_BYTES,
    objective_storage_component,
    opaque_identifier_component,
    owned_identifier_path,
)
from rookery.portable.writeups import (  # noqa: E402
    check_writeups,
    create_capsule,
    create_writeup,
)


@unittest.skipUnless(os.name == "posix", "requires POSIX filesystem modes")
class WriteupPathOwnershipTests(unittest.TestCase):
    def _create_capsule(self, root: Path, objective_id: str) -> None:
        create_capsule(
            mock.Mock(),
            root,
            objective_id=objective_id,
            action_reference="proposal:fixture",
            scorer_evidence="submissions/response.json",
            reproduction_path="exploit/solve.py",
            material_provenance=["analysis/report.md"],
            dead_path_checkpoint="none",
        )

    def test_invalid_objective_ids_fail_without_creating_artifacts(self) -> None:
        invalid_ids = (
            "",
            "\x00",
            "line\nbreak",
            "x" * (OPAQUE_IDENTIFIER_MAX_BYTES + 1),
            "é" * (OPAQUE_IDENTIFIER_MAX_BYTES // 2 + 1),
        )

        for creator in (
            lambda root, identifier: create_writeup(root, identifier, "Fixture"),
            self._create_capsule,
        ):
            for identifier in invalid_ids:
                with self.subTest(creator=creator.__name__, identifier=repr(identifier)):
                    with tempfile.TemporaryDirectory() as temporary:
                        root = Path(temporary)
                        with self.assertRaises(ValueError):
                            creator(root, identifier)
                        self.assertEqual(list(root.iterdir()), [])

    def test_objective_storage_component_hashes_safe_and_unsafe_ids(self) -> None:
        safe_id = "web-01.v2"
        safe_component = objective_storage_component(safe_id)
        raw_id = "../External Challenge/01"
        component = objective_storage_component(raw_id)

        self.assertTrue(safe_component.startswith("challenge-"))
        self.assertTrue(component.startswith("challenge-"))
        self.assertEqual(component, objective_storage_component(raw_id))
        self.assertNotIn("/", component)
        self.assertNotIn("\\", component)

    def test_objective_storage_component_prevents_safe_opaque_name_collision(self) -> None:
        unsafe_id = "../external-objective"
        unsafe_component = objective_storage_component(unsafe_id)
        safe_looking_id = unsafe_component

        self.assertNotEqual(
            objective_storage_component(safe_looking_id), unsafe_component
        )

    def test_safe_external_id_uses_its_opaque_storage_component(self) -> None:
        identifier = "web-01.v2"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = create_writeup(root, identifier, "Fixture")

            self.assertEqual(
                path.relative_to(root),
                Path("writeups")
                / objective_storage_component(identifier)
                / "WRITEUP.md",
            )
            self.assertTrue(path.exists())

    def test_helper_preserves_a_safe_attachment_name_without_creating_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = owned_identifier_path(
                root,
                root / "platform" / "challenges" / "101" / "files",
                "brief.v2.pdf",
                label="attachment_name",
            )

            self.assertEqual(
                destination.relative_to(root),
                Path("platform") / "challenges" / "101" / "files" / "brief.v2.pdf",
            )
            self.assertEqual(list(root.iterdir()), [])

    def test_opaque_identifier_component_is_stable_and_portable(self) -> None:
        external_name = "../briefs/Final Brief.PDF"

        component = opaque_identifier_component(
            external_name,
            label="attachment name",
            prefix="attachment",
        )

        self.assertEqual(
            component,
            "attachment-" + sha256(external_name.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(
            component,
            opaque_identifier_component(
                external_name,
                label="attachment name",
                prefix="attachment",
            ),
        )
        self.assertTrue(component.isascii())
        self.assertEqual(component, component.lower())

    def test_opaque_identifier_component_distinguishes_exact_external_values(self) -> None:
        first = opaque_identifier_component(
            "Brief.pdf", label="attachment name", prefix="attachment"
        )
        second = opaque_identifier_component(
            "brief.pdf", label="attachment name", prefix="attachment"
        )

        self.assertNotEqual(first, second)

    def test_opaque_identifier_component_rejects_invalid_input(self) -> None:
        invalid_values = (
            "",
            "line\nbreak",
            "control\x85character",
            "x" * (OPAQUE_IDENTIFIER_MAX_BYTES + 1),
            "é" * (OPAQUE_IDENTIFIER_MAX_BYTES // 2 + 1),
        )

        for value in invalid_values:
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValueError):
                    opaque_identifier_component(
                        value,
                        label="attachment name",
                        prefix="attachment",
                    )
        for prefix in ("", "Attachment", "a" * 64):
            with self.subTest(prefix=prefix):
                with self.assertRaises(ValueError):
                    opaque_identifier_component(
                        "safe external value",
                        label="attachment name",
                        prefix=prefix,
                    )

    def test_writeup_closeout_rejects_unowned_capsule_despite_completed_projection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            objective_id = "../escaped"
            canonical = {
                "objective_id": objective_id,
                "action_reference": "proposal:fixture",
                "scorer_evidence": "submissions/response.json",
                "reproduction_path": "exploit/solve.py",
                "material_provenance": ["analysis/report.md"],
                "dead_path_checkpoint": "none",
            }
            digest = sha256(canonical_json(canonical).encode("utf-8")).hexdigest()
            capsule = {
                "capsule_id": f"capsule_{digest}",
                **canonical,
                "canonical_sha256": digest,
                "created_at": "2026-08-28T00:00:00Z",
            }
            capsule_path = (
                root
                / "writeups"
                / objective_storage_component(objective_id)
                / "CAPSULE.json"
            )
            capsule_path.parent.mkdir(parents=True)
            capsule_path.write_text(json.dumps(capsule), encoding="utf-8")
            store = mock.Mock()
            store.rebuild.return_value = {
                "current": {
                    "solve_capsules": {},
                    "executions": {
                        "fixture": {
                            "objective_id": "../escaped",
                            "status": "completed",
                        }
                    },
                }
            }

            result = check_writeups(store, root, {"writeups": {}}, closeout=True)

            self.assertFalse(result["ok"])
            self.assertEqual(result["missing_capsules"], [])
            self.assertEqual(result["invalid_writeups"], [])
            self.assertEqual(
                result["unverified_capsules"],
                [{"objective_id": objective_id, "status": "unverified_legacy"}],
            )
            self.assertTrue(capsule_path.exists())

    def test_existing_symlinked_identifier_cannot_escape_writeups(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            tempfile.TemporaryDirectory() as external,
        ):
            root = Path(temporary)
            writeups = root / "writeups"
            ensure_private_dir(writeups)
            (writeups / objective_storage_component("linked")).symlink_to(
                external, target_is_directory=True
            )

            with self.assertRaises(ValueError):
                create_writeup(root, "linked", "Fixture")

            self.assertFalse((Path(external) / "WRITEUP.md").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
