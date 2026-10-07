from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT
from tests.rookery.env_fixtures import replace_env_assignments
from tests.rookery.test_preparation_and_isolation import copy_rookery

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable import baseline as baseline_module  # noqa: E402
from rookery.portable.baseline import (  # noqa: E402
    MeasurementBaselineError,
    build_measurement_baseline,
    configuration_digest,
    source_root_from_wrapper,
    verify_measurement_baseline,
    write_measurement_baseline,
)
from rookery.portable.manifest import resolve_manifest  # noqa: E402
from rookery.portable.release import build_release  # noqa: E402

UTC = dt.timezone.utc
PRIVATE_FIXTURE = "fixture-private-token-123"


class MeasurementBaselineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        copy_rookery(self.source)
        shutil.rmtree(self.source / ".ruff_cache", ignore_errors=True)
        environment_path = self.source / ".env"
        contents = environment_path.read_bytes()
        for key, value in {
            "ROCKYOU_PATH": PRIVATE_FIXTURE,
            "EVENT_ID": "fixture",
            "EVENT_NAME": "Fixture Event",
            "EVENT_SCOPE_ACK": "1",
            "ALLOWED_HOSTS": "fixture.invalid",
            "ALLOWED_PORTS": "443",
            "ALLOWED_PROTOCOLS": "https",
            "PLATFORM_HOSTS": "fixture.invalid",
            "SCOPE_MAX_BYTES": "1024",
        }.items():
            assignment = f"{key}=".encode("utf-8")
            self.assertIn(assignment, contents)
            contents = contents.replace(assignment, f"{key}={value}".encode("utf-8"), 1)
        environment_path.write_bytes(contents)
        self.artifacts = self.root / "artifacts"
        summary = build_release(self.source, self.artifacts)
        self.archive = self.artifacts / str(summary["archive"])
        self.manifest = self.artifacts / str(summary["manifest"])

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build(
        self, providers: tuple[str, ...] = (), *, hour: int = 1
    ) -> dict[str, object]:
        return build_measurement_baseline(
            self.source,
            self.archive,
            self.manifest,
            providers,
            now=dt.datetime(2026, 8, 28, hour, tzinfo=UTC),
        )

    def configure_output(self, output: Path, *, value: str | None = None) -> None:
        replace_env_assignments(
            self.source,
            {
                "ROOKERY_MEASUREMENT_BASELINE_PATH": value
                if value is not None
                else str(output.resolve()),
            },
        )

    def test_digest_is_stable_across_time_and_input_paths(self) -> None:
        first = self.build(hour=1)
        alternate_archive = self.root / "renamed-release.zip"
        alternate_manifest = self.root / "renamed-manifest.json"
        shutil.copy2(self.archive, alternate_archive)
        shutil.copy2(self.manifest, alternate_manifest)
        second = build_measurement_baseline(
            self.source,
            alternate_archive,
            alternate_manifest,
            now=dt.datetime(
                2026, 8, 29, 22, tzinfo=dt.timezone(dt.timedelta(hours=-4))
            ),
        )

        self.assertNotEqual(first["clock"], second["clock"])
        self.assertEqual(first["configuration_digest"], second["configuration_digest"])
        self.assertEqual(first["configuration_digest"], configuration_digest(first))
        self.assertNotIn(str(self.source), json.dumps(first))
        self.assertEqual(first["configuration"]["configuration_source"], "env")
        self.assertEqual(
            first["provider_fields"],
            {
                "queue": {"availability": "unavailable", "reason": "not_declared"},
                "tokens": {"availability": "unavailable", "reason": "not_declared"},
                "usage": {"availability": "unavailable", "reason": "not_declared"},
            },
        )

    def test_config_release_and_provider_changes_alter_digest(self) -> None:
        original = self.build()

        environment_path = self.source / ".env"
        environment_bytes = environment_path.read_bytes()
        self.assertIn(b"QUEUE_CADENCE_SECONDS=", environment_bytes)
        environment_path.write_bytes(
            environment_bytes.replace(
                b"QUEUE_CADENCE_SECONDS=", b"QUEUE_CADENCE_SECONDS=3", 1
            )
        )
        configured = self.build()
        environment_path.write_bytes(environment_bytes)

        readme_path = self.source / "README.md"
        readme_bytes = readme_path.read_bytes()
        readme_path.write_bytes(readme_bytes + b"\nRelease fixture change.\n")
        with self.assertRaisesRegex(
            MeasurementBaselineError, "source_manifest_content_mismatch"
        ):
            self.build()
        changed_artifacts = self.root / "changed-artifacts"
        changed_summary = build_release(self.source, changed_artifacts)
        release_changed = build_measurement_baseline(
            self.source,
            changed_artifacts / str(changed_summary["archive"]),
            changed_artifacts / str(changed_summary["manifest"]),
            now=dt.datetime(2026, 8, 28, 1, tzinfo=UTC),
        )
        readme_path.write_bytes(readme_bytes)

        provider_changed = self.build(
            ("queue=available", "tokens=unavailable:not_configured")
        )

        digests = {
            original["configuration_digest"],
            configured["configuration_digest"],
            release_changed["configuration_digest"],
            provider_changed["configuration_digest"],
        }
        self.assertEqual(len(digests), 4)
        self.assertEqual(
            provider_changed["provider_fields"]["queue"], {"availability": "available"}
        )
        self.assertEqual(
            provider_changed["provider_fields"]["usage"],
            {"availability": "unavailable", "reason": "not_declared"},
        )

    def test_legacy_event_file_is_not_read_or_bound(self) -> None:
        baseline_without_legacy = self.build()
        legacy = self.source / "event.json"
        legacy.write_bytes(
            b'{"identity":{"name":"legacy-private-sentinel"},"unterminated":'
        )

        baseline_with_legacy = self.build()

        self.assertEqual(
            baseline_with_legacy["configuration_digest"],
            baseline_without_legacy["configuration_digest"],
        )
        self.assertNotIn("legacy-private-sentinel", json.dumps(baseline_with_legacy))

    def test_write_requires_configured_matching_output_path(self) -> None:
        output = self.root / "operator" / "baseline.json"
        for value in ("", "unknown"):
            with self.subTest(value=value or "blank"):
                self.configure_output(output, value=value)
                with self.assertRaisesRegex(
                    MeasurementBaselineError, "configured_baseline_path_invalid"
                ):
                    write_measurement_baseline(
                        self.source, self.archive, self.manifest, output
                    )
                self.assertFalse(output.exists())

        self.configure_output(
            output, value=str((self.root / "different-baseline.json").resolve())
        )
        with self.assertRaisesRegex(
            MeasurementBaselineError, "configured_baseline_output_mismatch"
        ):
            write_measurement_baseline(
                self.source, self.archive, self.manifest, output
            )
        self.assertFalse(output.exists())

        relative = os.path.relpath(output, self.source)
        self.configure_output(output, value=relative)
        record = write_measurement_baseline(
            self.source, self.archive, self.manifest, output
        )
        self.assertEqual(record["record_kind"], "rookery.measurement_baseline")
        self.assertTrue(output.is_file())

    def test_runtime_state_is_refused_without_source_mutation_or_partial_output(
        self,
    ) -> None:
        state = self.source / "state"
        state.mkdir()
        canonical = state / "events.jsonl"
        canonical.write_bytes(b'{"event_type":"fixture"}\n')
        output = self.root / "baseline" / "record.json"
        self.configure_output(output)
        before = {
            path.relative_to(self.source).as_posix(): (
                path.read_bytes(),
                stat.S_IMODE(path.stat().st_mode),
                path.stat().st_mtime_ns,
            )
            for path in self.source.rglob("*")
            if path.is_file()
        }
        with self.assertRaisesRegex(MeasurementBaselineError, "runtime_state_present"):
            write_measurement_baseline(self.source, self.archive, self.manifest, output)

        after = {
            path.relative_to(self.source).as_posix(): (
                path.read_bytes(),
                stat.S_IMODE(path.stat().st_mode),
                path.stat().st_mtime_ns,
            )
            for path in self.source.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, after)
        self.assertFalse(output.exists())

    def test_wrapper_writes_private_record_without_secrets_or_paths(self) -> None:
        output = self.root / "operator" / "baseline.json"
        self.configure_output(output)
        completed = subprocess.run(
            [
                str(self.source / "bin" / "measurement-baseline"),
                "--archive",
                str(self.archive),
                "--manifest",
                str(self.manifest),
                "--output",
                str(output),
                "--provider-field",
                "provider_queue=available",
            ],
            cwd=self.root,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            text=True,
            capture_output=True,
            timeout=60,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        record = json.loads(output.read_text(encoding="utf-8"))
        rendered = (
            output.read_text(encoding="utf-8") + completed.stdout + completed.stderr
        )
        self.assertNotIn(PRIVATE_FIXTURE, rendered)
        self.assertNotIn(str(self.source), rendered)
        self.assertNotIn(str(output), rendered)
        self.assertEqual(record["schema_version"], "1")
        self.assertEqual(record["record_kind"], "rookery.measurement_baseline")
        self.assertEqual(
            record["provider_fields"]["queue"], {"availability": "available"}
        )
        self.assertTrue(record["validator"]["ok"])
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(
            source_root_from_wrapper(self.source / "bin" / "measurement-baseline"),
            self.source.resolve(),
        )

        original = output.read_bytes()
        with self.assertRaisesRegex(MeasurementBaselineError, "output_already_exists"):
            write_measurement_baseline(self.source, self.archive, self.manifest, output)
        self.assertEqual(output.read_bytes(), original)
        with self.assertRaisesRegex(MeasurementBaselineError, "output_inside_source"):
            write_measurement_baseline(
                self.source,
                self.archive,
                self.manifest,
                self.source / "baseline.json",
            )
        self.assertFalse((self.source / "baseline.json").exists())

    def test_output_refuses_filesystem_that_does_not_enforce_private_modes(
        self,
    ) -> None:
        output_parent = self.root / "public-output"
        output_parent.mkdir()
        output_parent.chmod(0o777)
        output = output_parent / "baseline.json"
        self.configure_output(output)

        with mock.patch("rookery.portable.util.os.fchmod", return_value=None):
            with self.assertRaisesRegex(
                MeasurementBaselineError, "output_publish_failed"
            ):
                write_measurement_baseline(
                    self.source,
                    self.archive,
                    self.manifest,
                    output,
                )

        self.assertFalse(output.exists())
        self.assertEqual(stat.S_IMODE(output_parent.stat().st_mode), 0o777)

    def test_malformed_and_oversized_inputs_fail_closed(self) -> None:
        bad_manifest = self.root / "bad-manifest.json"
        bad_manifest.write_text(
            '{"schema_version":"1","schema_version":"1"}', encoding="utf-8"
        )
        output = self.root / "bad-output.json"
        self.configure_output(output)
        with self.assertRaises(MeasurementBaselineError):
            write_measurement_baseline(self.source, self.archive, bad_manifest, output)
        self.assertFalse(output.exists())

        with mock.patch.object(baseline_module, "MAX_CONFIG_BYTES", 8):
            with self.assertRaisesRegex(
                MeasurementBaselineError, "environment_too_large"
            ):
                write_measurement_baseline(
                    self.source, self.archive, self.manifest, output
                )
        self.assertFalse(output.exists())

        with mock.patch.object(
            baseline_module, "MAX_ARCHIVE_BYTES", self.archive.stat().st_size - 1
        ):
            with self.assertRaisesRegex(MeasurementBaselineError, "archive_too_large"):
                write_measurement_baseline(
                    self.source, self.archive, self.manifest, output
                )
        self.assertFalse(output.exists())

        for invalid in (
            "queue=unavailable:",
            "queue=available:reason",
            "queue=unavailable:contains secret",
            "queue=available",
        ):
            declarations = (
                (invalid, invalid) if invalid == "queue=available" else (invalid,)
            )
            with self.assertRaisesRegex(
                MeasurementBaselineError, "provider_field_invalid"
            ):
                write_measurement_baseline(
                    self.source,
                    self.archive,
                    self.manifest,
                    output,
                    declarations,
                )
            self.assertFalse(output.exists())

    def test_launch_verifier_binds_current_configuration_and_rejects_tamper(
        self,
    ) -> None:
        output = self.root / "operator" / "baseline.json"
        self.configure_output(output)
        record = write_measurement_baseline(
            self.source,
            self.archive,
            self.manifest,
            output,
            ("queue=available", "tokens=available", "usage=unavailable:not_configured"),
        )
        resolved = resolve_manifest(self.source)
        verified = verify_measurement_baseline(
            self.source,
            output,
            resolved.manifest,
            verify_source_tree=True,
        )
        self.assertEqual(verified["configuration_digest"], record["configuration_digest"])
        self.assertEqual(verified["sha256"], baseline_module._bounded_file_hash(output, baseline_module.MAX_CONFIG_BYTES, "fixture")[0])
        self.assertEqual(
            verified["measurement_contract"],
            {
                "queue_automation_enabled": False,
                "provider_fields": {
                    "queue": {"availability": "available"},
                    "tokens": {"availability": "available"},
                    "usage": {"availability": "unavailable"},
                },
            },
        )

        tampered = json.loads(output.read_text(encoding="utf-8"))
        tampered["configuration_digest"] = "0" * 64
        output.write_text(json.dumps(tampered), encoding="utf-8")
        output.chmod(0o600)
        with self.assertRaisesRegex(MeasurementBaselineError, "measurement_baseline_invalid"):
            verify_measurement_baseline(
                self.source,
                output,
                resolved.manifest,
                verify_source_tree=True,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
