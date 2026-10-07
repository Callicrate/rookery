from __future__ import annotations

import json
import os
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

from rookery.portable.baseline import _safe_configuration
from rookery.portable.environment import EnvironmentPolicyError
from rookery.portable.manifest import available_logical_cpu_count, resolve_manifest
from rookery.portable.registry import _render_codex_files
from tests.rookery.support import ROOKERY_ROOT


class ConcurrencyConfigTests(unittest.TestCase):
    def test_static_configs_use_safe_modern_bootstrap_cap(self) -> None:
        profile = json.loads(
            (ROOKERY_ROOT / "profiles" / "generic.json").read_text(encoding="utf-8")
        )
        self.assertEqual(profile["concurrency"]["max_workers"], "auto")
        self.assertEqual(profile["concurrency"]["max_subagent_threads"], 96)
        self.assertEqual(profile["concurrency"]["max_agent_depth"], 2)

        for relative in (
            ".codex/config.toml",
            "configs/codex-base.toml",
        ):
            with self.subTest(relative=relative):
                with (ROOKERY_ROOT / relative).open("rb") as handle:
                    configuration = tomllib.load(handle)
                self.assertNotIn("max_threads", configuration["agents"])
                self.assertEqual(
                    int(
                        configuration["agents"][
                            "max_concurrent_threads_per_session"
                        ]
                    ),
                    96,
                )
                self.assertEqual(configuration["agents"]["max_depth"], 2)

    def test_available_cpu_count_prefers_process_affinity(self) -> None:
        with (
            mock.patch(
                "rookery.portable.manifest.os.sched_getaffinity",
                return_value={0, 2, 4},
                create=True,
            ),
            mock.patch("rookery.portable.manifest.os.cpu_count", return_value=32),
        ):
            self.assertEqual(available_logical_cpu_count(), 3)

    def test_available_cpu_count_falls_back_to_one(self) -> None:
        with (
            mock.patch(
                "rookery.portable.manifest.os.sched_getaffinity",
                side_effect=OSError("unsupported"),
                create=True,
            ),
            mock.patch(
                "rookery.portable.manifest.os.process_cpu_count",
                return_value=None,
                create=True,
            ),
            mock.patch("rookery.portable.manifest.os.cpu_count", return_value=None),
        ):
            self.assertEqual(available_logical_cpu_count(), 1)

    def test_available_cpu_count_uses_process_count_before_system_count(self) -> None:
        with (
            mock.patch(
                "rookery.portable.manifest.os.sched_getaffinity",
                side_effect=OSError("unsupported"),
                create=True,
            ),
            mock.patch(
                "rookery.portable.manifest.os.process_cpu_count",
                return_value=5,
                create=True,
            ),
            mock.patch("rookery.portable.manifest.os.cpu_count", return_value=32),
        ):
            self.assertEqual(available_logical_cpu_count(), 5)

    def test_auto_worker_count_resolves_before_manifest_is_returned(self) -> None:
        with mock.patch(
            "rookery.portable.manifest.available_logical_cpu_count", return_value=24
        ):
            result = resolve_manifest(
                ROOKERY_ROOT,
                env={"PLATFORM_ADAPTER": "manual"},
            )

        self.assertEqual(result.manifest["concurrency"]["max_workers"], 24)

    def test_explicit_worker_count_overrides_auto_detection(self) -> None:
        with mock.patch(
            "rookery.portable.manifest.available_logical_cpu_count", return_value=24
        ) as detector:
            result = resolve_manifest(
                ROOKERY_ROOT,
                env={
                    "PLATFORM_ADAPTER": "manual",
                    "CONCURRENCY_MAX_WORKERS": "7",
                },
            )

        self.assertEqual(result.manifest["concurrency"]["max_workers"], 7)
        detector.assert_not_called()

    def test_non_positive_worker_override_fails_environment_validation(self) -> None:
        with self.assertRaisesRegex(
            EnvironmentPolicyError,
            "event_environment_invalid:CONCURRENCY_MAX_WORKERS",
        ):
            resolve_manifest(
                ROOKERY_ROOT,
                env={
                    "PLATFORM_ADAPTER": "manual",
                    "CONCURRENCY_MAX_WORKERS": "0",
                },
            )

    def test_legacy_instance_controls_are_rejected(self) -> None:
        for name in (
            "CODEX_CLI_MAX_INSTANCES",
            "CODEX_SUBAGENT_THREADS_PER_INSTANCE",
        ):
            with self.subTest(name=name), self.assertRaisesRegex(
                EnvironmentPolicyError,
                f"event_environment_undeclared:{name}",
            ):
                resolve_manifest(
                    ROOKERY_ROOT,
                    env={"PLATFORM_ADAPTER": "manual", name: "1"},
                )

    @unittest.skipUnless(os.name == "posix", "surface rendering requires POSIX")
    def test_renderer_writes_per_session_subagent_count_to_codex_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".codex").mkdir()
            (root / ".codex" / "config.toml").write_text("", encoding="utf-8")
            template = root / "template.toml"
            template.write_bytes(
                b"[agents]\r\n"
                b"max_concurrent_threads_per_session = 96\r\n"
                b"max_depth = 2\r\n"
            )

            _render_codex_files(
                root,
                [],
                template,
                max_concurrent_threads=96,
                strict_config_supported=False,
            )

            with (root / ".codex" / "config.toml").open("rb") as handle:
                rendered = tomllib.load(handle)
            self.assertEqual(
                rendered["agents"]["max_concurrent_threads_per_session"], 96
            )
            self.assertIn(
                b"max_concurrent_threads_per_session = 96\r\n",
                (root / ".codex" / "config.toml").read_bytes(),
            )

    def test_subagent_limit_is_independent_of_native_workers(self) -> None:
        result = resolve_manifest(
            ROOKERY_ROOT,
            env={
                "PLATFORM_ADAPTER": "manual",
                "CONCURRENCY_MAX_WORKERS": "2",
                "CODEX_SUBAGENT_THREADS": "96",
            },
        )
        self.assertNotIn(
            "concurrency.max_subagent_threads must not exceed max_workers",
            result.errors,
        )
        self.assertEqual(result.manifest["concurrency"]["max_workers"], 2)
        self.assertEqual(result.manifest["concurrency"]["max_subagent_threads"], 96)
        baseline_configuration = _safe_configuration(result.manifest)
        self.assertEqual(
            baseline_configuration["concurrency"],
            {
                "max_workers": 2,
                "max_jobs": 8,
                "max_subagent_threads": 96,
                "max_agent_depth": 2,
            },
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
