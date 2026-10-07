from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT
from tests.rookery.env_fixtures import (
    configure_event_environment,
    replace_env_assignments,
)
from tests.rookery.test_preparation_and_isolation import copy_rookery

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.release import ReleaseBuildError, build_release, source_root_from_wrapper  # noqa: E402
from rookery.portable import release as release_module  # noqa: E402
from rookery.portable.manifest import resolve_manifest  # noqa: E402
from rookery.portable.validator import validate_tree  # noqa: E402


class ReleaseBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.source = Path(self.temporary.name) / "source"
        copy_rookery(self.source)
        shutil.copyfile(self.source / ".env.example", self.source / ".env")
        shutil.rmtree(self.source / ".ruff_cache", ignore_errors=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_mutation_rejected(self, mutate) -> None:
        output = Path(self.temporary.name) / "mutation-output"
        original_fsync = release_module._fsync

        def mutate_after_archive(path: Path) -> None:
            original_fsync(path)
            mutate()

        with mock.patch.object(release_module, "_fsync", side_effect=mutate_after_archive):
            with self.assertRaisesRegex(ReleaseBuildError, "release_source_changed"):
                build_release(self.source, output)
        self.assertFalse(output.exists() and any(output.iterdir()))

    def extract_with_archive_modes(self, archive_path: Path) -> Path:
        extracted = Path(self.temporary.name) / "extracted"
        with zipfile.ZipFile(archive_path) as archive:
            for info in archive.infolist():
                destination = extracted / info.filename
                if info.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.read(info))
                os.chmod(destination, (info.external_attr >> 16) & 0o777)
        return extracted / "rookery"

    def test_repeatable_contents_hashes_modes_and_wrapper_source_root(self) -> None:
        live_sentinel = b"source-only-private-sentinel"
        environment_path = self.source / ".env"
        environment_path.write_bytes(
            environment_path.read_bytes().replace(
                b"ROCKYOU_PATH=\n", b"ROCKYOU_PATH=" + live_sentinel + b"\n", 1
            )
        )
        first_output = Path(self.temporary.name) / "first-output"
        second_output = Path(self.temporary.name) / "second-output"
        first = build_release(self.source, first_output)
        second = build_release(self.source, second_output)
        first_archive = first_output / str(first["archive"])
        second_archive = second_output / str(second["archive"])
        first_manifest = first_output / str(first["manifest"])
        second_manifest = second_output / str(second["manifest"])

        self.assertEqual(first_archive.read_bytes(), second_archive.read_bytes())
        self.assertEqual(
            hashlib.sha256(first_archive.read_bytes()).hexdigest(),
            first["archive_sha256"],
        )
        self.assertEqual(first_manifest.read_bytes(), second_manifest.read_bytes())
        self.assertEqual(
            (first_output / str(first["sha256_sidecar"])).read_text(encoding="ascii"),
            f"{first['archive_sha256']}  {first['archive']}\n",
        )
        manifest = json.loads(first_manifest.read_text(encoding="utf-8"))
        self.assertEqual([row["path"] for row in manifest["files"]], sorted(row["path"] for row in manifest["files"]))
        expected_paths = sorted(
            path.relative_to(self.source).as_posix()
            for path in self.source.rglob("*")
            if path.is_file() and not path.is_symlink()
        )
        self.assertEqual([row["path"] for row in manifest["files"]], expected_paths)
        installed_environment = (self.source / ".env.example").read_bytes()
        self.assertIn(b"ROOKERY_ALLOW_INSTALL_NETWORK=0\n", installed_environment)
        self.assertIn(
            b"SEARXNG_IMAGE=ghcr.io/searxng/searxng:2026.8.28-a30b2d474"
            b"@sha256:addd2cf36efb4b9815a2820a522aef7cce4da0d1c0e4527f6675f5663332fc9b\n",
            installed_environment,
        )
        self.assertNotIn(b"CHROME_FOR_TESTING_CHANNEL", installed_environment)
        self.assertNotIn(b"searxng/searxng:latest", installed_environment)
        environment_row = next(row for row in manifest["files"] if row["path"] == ".env")
        self.assertEqual(environment_row["bytes"], len(installed_environment))
        self.assertEqual(
            environment_row["sha256"],
            hashlib.sha256(installed_environment).hexdigest(),
        )
        self.assertEqual(environment_row["mode"], "0600")
        with zipfile.ZipFile(first_archive) as archive:
            names = archive.namelist()
            self.assertEqual(names, sorted(names))
            for skill in (
                "rookery-browser-bridge",
                "rookery-browser-scoring",
                "rookery-event-preparation",
                "rookery-event-retrospective",
            ):
                self.assertIn(
                    f"rookery/.agents/skills/{skill}/SKILL.md",
                    names,
                )
            self.assertFalse(
                any("/.agents/skills/rookery-maintainer-" in name for name in names)
            )
            for row in manifest["files"]:
                self.assertEqual(
                    hashlib.sha256(archive.read(f"rookery/{row['path']}")).hexdigest(),
                    row["sha256"],
                )
            self.assertEqual((archive.getinfo("rookery/").external_attr >> 16) & 0o777, 0o755)
            self.assertEqual((archive.getinfo("rookery/go").external_attr >> 16) & 0o777, 0o755)
            self.assertEqual((archive.getinfo("rookery/run-codex").external_attr >> 16) & 0o777, 0o755)
            self.assertEqual((archive.getinfo("rookery/bin/rookery").external_attr >> 16) & 0o777, 0o755)
            self.assertEqual((archive.getinfo("rookery/.env").external_attr >> 16) & 0o777, 0o600)
            self.assertEqual((archive.getinfo("rookery/lib/rookery/portable/util.py").external_attr >> 16) & 0o777, 0o644)
            self.assertEqual(archive.read("rookery/.env"), installed_environment)
        self.assertFalse(live_sentinel in first_archive.read_bytes(), "live .env leaked into archive")
        self.assertFalse(live_sentinel in first_manifest.read_bytes(), "live .env leaked into manifest")
        self.assertFalse(live_sentinel.decode("ascii") in json.dumps(first), "live .env leaked into summary")
        extracted_report = validate_tree(
            self.extract_with_archive_modes(first_archive),
            strict_release=True,
            source_checkout=True,
        )
        self.assertTrue(extracted_report["ok"], extracted_report["errors"])
        self.assertEqual(source_root_from_wrapper(self.source / "bin" / "build-release"), self.source.resolve())

    def test_untracked_empty_directories_do_not_change_release_members(self) -> None:
        first_output = Path(self.temporary.name) / "first-output"
        second_output = Path(self.temporary.name) / "second-output"
        first = build_release(self.source, first_output)

        (self.source / "docs" / "empty-untracked" / "nested").mkdir(parents=True)
        (self.source / "adapters" / "empty-untracked").mkdir()
        second = build_release(self.source, second_output)

        first_archive = first_output / str(first["archive"])
        second_archive = second_output / str(second["archive"])
        first_manifest = first_output / str(first["manifest"])
        second_manifest = second_output / str(second["manifest"])
        self.assertEqual(first_archive.read_bytes(), second_archive.read_bytes())
        self.assertEqual(first_manifest.read_bytes(), second_manifest.read_bytes())

        manifest = json.loads(second_manifest.read_text(encoding="utf-8"))
        directories = {row["path"] for row in manifest["directories"]}
        self.assertIn("lib", directories)
        self.assertIn("lib/rookery", directories)
        self.assertIn("lib/rookery/portable", directories)
        self.assertFalse(any(path.startswith("docs/empty-untracked") for path in directories))
        self.assertFalse(any(path.startswith("adapters/empty-untracked") for path in directories))
        with zipfile.ZipFile(second_archive) as archive:
            names = set(archive.namelist())
        self.assertIn("rookery/lib/rookery/portable/", names)
        self.assertFalse(any("empty-untracked" in name for name in names))

    def test_skill_roots_separate_maintainer_and_operational_workflows(self) -> None:
        maintainer_root = ROOKERY_ROOT.parent / ".agents" / "skills"
        operational_root = ROOKERY_ROOT / ".agents" / "skills"
        self.assertEqual(
            {
                path.name
                for path in maintainer_root.iterdir()
                if (path / "SKILL.md").is_file()
            },
            {
                "rookery-maintainer-adapter-development",
                "rookery-maintainer-release-hygiene",
            },
        )
        self.assertEqual(
            {
                path.name
                for path in operational_root.iterdir()
                if (path / "SKILL.md").is_file()
            },
            {
                "rookery-browser-bridge",
                "rookery-browser-scoring",
                "rookery-event-preparation",
                "rookery-event-retrospective",
            },
        )

    def test_adapter_only_release_keeps_htb_and_omits_other_bundles(self) -> None:
        output = Path(self.temporary.name) / "htb-output"
        summary = build_release(self.source, output, selected_adapter="htb")
        self.assertEqual(summary["selected_adapter"], "htb")
        archive_path = output / str(summary["archive"])
        manifest_path = output / str(summary["manifest"])
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        paths = {row["path"] for row in manifest["files"]}

        self.assertIn("adapters/htb/adapter.json", paths)
        self.assertIn(
            "adapters/htb/agents/ctf_htb_sherlock_analyst.toml", paths
        )
        for forbidden in (
            "adapters/ctfd/",
            "adapters/immersive/",
            "extensions/",
        ):
            self.assertFalse(any(path.startswith(forbidden) for path in paths))
        with zipfile.ZipFile(archive_path) as archive:
            names = set(archive.namelist())
            self.assertIn("rookery/adapters/htb/adapter.json", names)
            self.assertFalse(
                any(
                    name.startswith(
                        (
                            "rookery/adapters/ctfd/",
                            "rookery/adapters/immersive/",
                            "rookery/extensions/",
                        )
                    )
                    for name in names
                )
            )
        extracted_report = validate_tree(
            self.extract_with_archive_modes(archive_path),
            strict_release=True,
            source_checkout=True,
        )
        self.assertTrue(extracted_report["ok"], extracted_report["errors"])

    def test_adapter_only_immersive_includes_reviewed_default_extension(self) -> None:
        output = Path(self.temporary.name) / "immersive-output"
        report = validate_tree(self.source, strict_release=True, source_checkout=True)
        self.assertTrue(report["ok"], report["errors"])
        summary = build_release(self.source, output, selected_adapter="immersive")
        archive_path = output / str(summary["archive"])
        extracted = self.extract_with_archive_modes(archive_path)
        with zipfile.ZipFile(archive_path) as archive:
            names = set(archive.namelist())
        self.assertIn("rookery/adapters/immersive/adapter.json", names)
        self.assertIn("rookery/extensions/guacamole/extension.json", names)
        self.assertFalse(any(name.startswith("rookery/extensions/koth/") for name in names))
        resolved = resolve_manifest(
            extracted, env={"PLATFORM_ADAPTER": "immersive"}, parent={}
        )
        self.assertFalse(resolved.errors, resolved.errors)
        self.assertIn("guacamole", resolved.manifest["surface"]["extensions"])

    def test_adapter_only_release_rejects_missing_or_unsafe_adapter(self) -> None:
        for adapter, expected in (
            ("missing", "selected_adapter_missing"),
            ("../htb", "invalid_selected_adapter"),
        ):
            with self.subTest(adapter=adapter):
                output = Path(self.temporary.name) / f"blocked-{adapter.replace('/', '-')}"
                with self.assertRaisesRegex(ReleaseBuildError, expected):
                    build_release(self.source, output, selected_adapter=adapter)
                self.assertFalse(output.exists())

    def test_added_source_file_after_archive_is_rejected_before_publish(self) -> None:
        self.assert_mutation_rejected(
            lambda: (self.source / "docs" / "concurrent-added.md").write_text(
                "added during archive", encoding="utf-8"
            )
        )

    def test_removed_source_file_after_archive_is_rejected_before_publish(self) -> None:
        self.assert_mutation_rejected(lambda: (self.source / "README.md").unlink())

    def test_same_size_source_change_after_archive_is_rejected_before_publish(self) -> None:
        target = self.source / "README.md"

        def mutate() -> None:
            original = target.read_bytes()
            replacement = b"X" if original[:1] != b"X" else b"Y"
            target.write_bytes(replacement + original[1:])

        self.assert_mutation_rejected(mutate)

    def test_live_environment_change_after_archive_is_rejected_before_publish(self) -> None:
        environment = self.source / ".env"
        original = environment.read_bytes()

        def mutate() -> None:
            environment.write_bytes(original + b"\nLOCAL_PRIVATE_MUTATION=changed\n")

        self.assert_mutation_rejected(mutate)

    def test_live_event_environment_change_after_archive_is_rejected_before_publish(self) -> None:
        def mutate() -> None:
            replace_env_assignments(
                self.source, {"EVENT_NAME": "Concurrent private mutation"}
            )

        self.assert_mutation_rejected(mutate)

    def test_clean_source_synthesizes_required_configuration_from_examples(self) -> None:
        (self.source / ".env").unlink()

        installed_report = validate_tree(self.source, strict_release=True)
        self.assertIn("required release path missing: .env", installed_report["errors"])
        report = validate_tree(self.source, strict_release=True, source_checkout=True)
        self.assertTrue(report["ok"], report["errors"])
        output = Path(self.temporary.name) / "template-only-output"
        summary = build_release(self.source, output)
        archive_path = output / str(summary["archive"])
        manifest = json.loads((output / str(summary["manifest"])).read_text(encoding="utf-8"))
        manifest_files = {row["path"]: row for row in manifest["files"]}

        self.assertEqual(
            manifest_files[".env"]["sha256"],
            hashlib.sha256((self.source / ".env.example").read_bytes()).hexdigest(),
        )
        with zipfile.ZipFile(archive_path) as archive:
            self.assertEqual(archive.read("rookery/.env"), (self.source / ".env.example").read_bytes())
            self.assertNotIn("rookery/event.json", archive.namelist())
        extracted_report = validate_tree(
            self.extract_with_archive_modes(archive_path),
            strict_release=True,
            source_checkout=True,
        )
        self.assertTrue(extracted_report["ok"], extracted_report["errors"])

    def test_source_checkout_validation_mode_is_explicit(self) -> None:
        (self.source / ".env").unlink()
        environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}

        installed = subprocess.run(
            [sys.executable, str(self.source / "bin" / "validate_rookery.py"), "--release"],
            cwd=self.source,
            env=environment,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(installed.returncode, 1, installed.stderr)
        self.assertIn("required release path missing: .env", installed.stdout)

        source = subprocess.run(
            [
                sys.executable,
                str(self.source / "bin" / "validate_rookery.py"),
                "--release",
                "--source-checkout",
            ],
            cwd=self.source,
            env=environment,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(source.returncode, 0, source.stderr)
        self.assertTrue(json.loads(source.stdout)["ok"])

        invalid = subprocess.run(
            [
                sys.executable,
                str(self.source / "bin" / "validate_rookery.py"),
                "--source-checkout",
            ],
            cwd=self.source,
            env=environment,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(invalid.returncode, 2)
        self.assertIn("--source-checkout requires --release", invalid.stderr)

    def test_live_operator_credentials_are_not_release_payloads(self) -> None:
        environment = self.source / ".env"
        original = environment.read_bytes()
        for name, value, extra in (
            (
                "CTFD_TOKEN",
                "fixture-session-value-123456",
                {"CTFD_TOKEN": "fixture-session-value-123456"},
            ),
            (
                "HTTPS_PROXY",
                "http://fixture-auth-value-123456@proxy.invalid",
                {
                    "CTFD_TOKEN": "fixture-required-token",
                    "CTFD_NETWORK_ENV_KEYS": '["HTTPS_PROXY"]',
                    "HTTPS_PROXY": "http://fixture-auth-value-123456@proxy.invalid",
                },
            ),
        ):
            with self.subTest(name=name):
                environment.write_bytes(original)
                configure_event_environment(
                    self.source,
                    "ctfd",
                    extra={
                        "CTFD_URL": "https://fixture.invalid",
                        "ADAPTER_CONFIG_BASE_URL": "https://fixture.invalid",
                        **extra,
                    },
                )
                report = validate_tree(
                    self.source, adapter="ctfd", strict_release=True, source_checkout=True
                )
                self.assertTrue(report["ok"], report["errors"])
                output = Path(self.temporary.name) / f"operator-{name.lower()}"
                summary = build_release(self.source, output)
                archive = output / str(summary["archive"])
                manifest = output / str(summary["manifest"])
                self.assertNotIn(value.encode("ascii"), archive.read_bytes())
                self.assertNotIn(value, manifest.read_text(encoding="utf-8"))
        environment.write_bytes(original)

    def test_shipped_template_credentials_fail_without_release_artifacts(self) -> None:
        template = self.source / ".env.example"
        original = template.read_bytes()
        value = "fixture-template-secret-123456"
        template.write_bytes(original + f"\nSESSION_ID={value}\n".encode("ascii"))
        report = validate_tree(
            self.source, strict_release=True, source_checkout=True
        )
        self.assertIn("secret-shaped assignment in .env.example", report["errors"])
        output = Path(self.temporary.name) / "blocked-template-secret"
        with self.assertRaisesRegex(ReleaseBuildError, "strict_release_validation_failed") as raised:
            build_release(self.source, output)
        self.assertNotIn(value, str(raised.exception))
        self.assertFalse(output.exists())
        template.write_bytes(original)

    def test_forbidden_symlink_output_root_and_limits_fail_without_final_artifacts(self) -> None:
        output = Path(self.temporary.name) / "rejected-output"
        self.assertTrue(
            validate_tree(
                self.source, strict_release=True, source_checkout=True
            )["ok"]
        )
        (self.source / "START_PROMPT.md").write_text("runtime", encoding="utf-8")
        with self.assertRaisesRegex(ReleaseBuildError, "strict_release_validation_failed"):
            build_release(self.source, output)
        self.assertFalse(output.exists())
        (self.source / "START_PROMPT.md").unlink()
        self.assertTrue(
            validate_tree(
                self.source, strict_release=True, source_checkout=True
            )["ok"]
        )
        link = self.source / "docs" / "inside-link"
        link.symlink_to(self.source / "README.md")
        with self.assertRaisesRegex(ReleaseBuildError, "release_symlink_rejected"):
            build_release(self.source, output)
        self.assertFalse(output.exists())
        link.unlink()
        self.assertTrue(
            validate_tree(
                self.source, strict_release=True, source_checkout=True
            )["ok"]
        )
        if os.name == "posix":
            # Keep the FIFO outside the static Python source roots so source
            # validation stays clean and the builder's inventory layer owns
            # the special-file rejection.
            pipe = self.source / "docs" / "release-builder-pipe"
            os.mkfifo(pipe)
            self.assertTrue(
                validate_tree(
                    self.source, strict_release=True, source_checkout=True
                )["ok"]
            )
            with self.assertRaisesRegex(ReleaseBuildError, "release_non_regular_file"):
                build_release(self.source, output)
            pipe.unlink()
        self.assertTrue(
            validate_tree(
                self.source, strict_release=True, source_checkout=True
            )["ok"]
        )
        with self.assertRaisesRegex(ReleaseBuildError, "output_inside_source"):
            build_release(self.source, self.source / "artifacts")
        with self.assertRaisesRegex(ReleaseBuildError, "release_file_limit_exceeded"):
            build_release(self.source, output, max_files=1)
        self.assertFalse(output.exists())
        with self.assertRaisesRegex(ReleaseBuildError, "release_byte_limit_exceeded"):
            build_release(self.source, output, max_total_bytes=1)
        self.assertFalse(output.exists())

    def test_wrapper_builds_privacy_safe_summary(self) -> None:
        output = Path(self.temporary.name) / "wrapper-output"
        environment = {
            **os.environ,
            "PYTHONPATH": str(self.source / "lib"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        completed = subprocess.run(
            [sys.executable, str(self.source / "bin" / "build-release"), "--output-dir", str(output)],
            cwd=self.temporary.name,
            env=environment,
            text=True,
            capture_output=True,
            timeout=30,
        )
        summary = json.loads(completed.stdout)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(summary["ok"])
        self.assertNotIn(str(self.source), completed.stdout)
        self.assertTrue((output / summary["archive"]).is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
