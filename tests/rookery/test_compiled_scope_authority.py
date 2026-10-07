from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.support import (
    ROOKERY_ROOT,
    copy_non_deployed_rookery,
    install_test_launch_binding,
)
from tests.rookery.env_fixtures import configure_event_environment

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

# ruff: noqa: E402
from rookery.portable.manifest import resolve_manifest
from rookery.portable.scope import (
    ScopeAuthorityError,
    _canonical_scope,
    compile_scope,
    load_canonical_compiled_scope,
    verify_canonical_compiled_scope_binding,
)
from rookery.portable.environment import (
    EnvironmentPolicyError,
    read_launch_binding,
    verify_launch_binding_integrity,
)
from rookery.portable.store import EventStore


@unittest.skipUnless(os.name == "posix", "requires POSIX mutation-lock semantics")
class CompiledScopeAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        copy_non_deployed_rookery(self.root)
        self.state = self.root / "state"
        self.state.mkdir(exist_ok=True)
        self._write_event()
        install_test_launch_binding(self.root)
        self._write_database(scope_generation=7, stop_generation=3)
        self._write_current_scope()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_event(self, *, cidrs: list[str] | None = None, ports: list[int] | None = None) -> None:
        configure_event_environment(
            self.root,
            "manual",
            name_suffix="Scope Authority",
            extra={
                "EVENT_ID": "scope-authority",
                "ALLOWED_HOSTS": "fixture.invalid",
                "ALLOWED_CIDRS": ",".join(
                    cidrs if cidrs is not None else ["10.10.0.0/16"]
                ),
                "ALLOWED_PORTS": ",".join(
                    str(port) for port in (ports if ports is not None else [22, 443])
                ),
                "ALLOWED_PROTOCOLS": "tcp,https",
                "ALLOWED_FILE_ORIGINS": "",
                "PLATFORM_HOSTS": "",
                "SCOPE_MAX_BYTES": "4096",
                "ANSWER_EXAMPLES_JSON": '["FIXTURE{scope}"]',
            },
        )

    def _write_database(self, *, scope_generation: int, stop_generation: int) -> None:
        store = EventStore(self.root, launch_binding=read_launch_binding(self.root))
        store.set_meta("scope_generation", scope_generation)
        store.set_meta("stop_generation", stop_generation)

    def _control_event(self, event_type: str, *, actor: str = "operator") -> None:
        store = EventStore(self.root, launch_binding=read_launch_binding(self.root))
        if event_type == "control.stop":
            stop_generation = store.current_stop_generation() + 1
            store.set_meta("stop_generation", stop_generation)
        else:
            stop_generation = store.current_stop_generation()
        store.append(
            event_type,
            {"generation": stop_generation, "reason": "fixture control"},
            actor=actor,
            generation=stop_generation,
        )

    def _expected_scope(self) -> dict[str, object]:
        result = resolve_manifest(self.root)
        self.assertFalse(result.errors)
        return compile_scope(result.manifest, 7)

    def _write_current_scope(self) -> None:
        resolved = resolve_manifest(self.root)
        self.assertFalse(resolved.errors)
        (self.state / "resolved_event.json").write_text(
            json.dumps(resolved.manifest), encoding="utf-8"
        )
        (self.state / "scope.json").write_text(
            json.dumps(compile_scope(resolved.manifest, 7)), encoding="utf-8"
        )

    def test_schema2_scope_matching_manifest_and_sqlite_is_admitted(self) -> None:
        binding = load_canonical_compiled_scope(self.root)
        self.assertEqual(binding.scope_generation, 7)
        self.assertEqual(binding.stop_generation, 3)
        self.assertEqual(binding.scope["schema_version"], "2")
        self.assertEqual(len(binding.file_sha256), 64)
        self.assertEqual(
            verify_canonical_compiled_scope_binding(
                self.root,
                scope_generation=binding.scope_generation,
                stop_generation=binding.stop_generation,
                file_sha256=binding.file_sha256,
                content_sha256=binding.content_sha256,
                launch_binding_sha256=binding.launch_binding_sha256,
            ).scope,
            binding.scope,
        )

    def test_selected_adapter_configuration_remains_part_of_scope_binding(self) -> None:
        configure_event_environment(
            self.root,
            "ctfd_browser_gateway",
            name_suffix="Gateway Scope",
            extra={
                "EVENT_ID": "gateway-scope-authority",
                "ALLOWED_HOSTS": "fixture.invalid,ctfd.fixture",
                "PLATFORM_HOSTS": "ctfd.fixture",
                "ALLOWED_PORTS": "443",
                "ALLOWED_PROTOCOLS": "https",
                "CTFD_URL": "https://ctfd.fixture",
                "CTFD_TOKEN": "fixture-only-token",
                "BROWSER_MODE": "cdp",
                "BROWSER_CDP_URL": "http://127.0.0.1:9001",
                "BROWSER_GATEWAY_URL": "http://127.0.0.1:9003",
                "ADAPTER_CONFIG_BASE_URL": "https://ctfd.fixture",
                "ADAPTER_CONFIG_SCORING_MODE": "team",
                "ADAPTER_CONFIG_EXPECTED_ACCOUNT_ID": "account-7",
                "ADAPTER_CONFIG_EXPECTED_TEAM_ID": "team-9",
                "ADAPTER_CONFIG_CSRF_PAGE_PATH": "/challenges",
                "ADAPTER_CONFIG_SESSION_LEASE_SECONDS": "60",
                "ADAPTER_CONFIG_TIMEOUT": "30",
                "ADAPTER_CONFIG_MAX_RESPONSE_BYTES": "262144",
                "ADAPTER_CONFIG_BROWSER_SUPPORT_ORIGINS": "[]",
            },
        )
        install_test_launch_binding(self.root)
        self._write_current_scope()
        binding = load_canonical_compiled_scope(self.root)
        self.assertEqual(binding.scope["platform_hosts"], ["ctfd.fixture"])

    def test_schemaless_and_same_generation_widening_are_refused(self) -> None:
        path = self.state / "scope.json"
        forged = dict(self._expected_scope())
        forged.pop("schema_version")
        path.write_text(json.dumps(forged), encoding="utf-8")
        with self.assertRaises(ScopeAuthorityError):
            load_canonical_compiled_scope(self.root)

        forged = dict(self._expected_scope())
        forged["allowed_cidrs"] = ["10.0.0.0/8"]
        path.write_text(json.dumps(forged), encoding="utf-8")
        with self.assertRaises(ScopeAuthorityError):
            load_canonical_compiled_scope(self.root)

    def test_port_host_manifest_and_sqlite_generation_drift_are_refused(self) -> None:
        forged = dict(self._expected_scope())
        forged["allowed_ports"] = [22, 443, 8443]
        (self.state / "scope.json").write_text(json.dumps(forged), encoding="utf-8")
        with self.assertRaises(ScopeAuthorityError):
            load_canonical_compiled_scope(self.root)

        self._write_current_scope()
        self._write_event(cidrs=["10.11.0.0/16"])
        with self.assertRaises(ScopeAuthorityError):
            load_canonical_compiled_scope(self.root)

        self._write_event()
        self._write_database(scope_generation=8, stop_generation=3)
        with self.assertRaises(ScopeAuthorityError):
            load_canonical_compiled_scope(self.root)

    def test_manifest_race_and_post_plan_scope_or_stop_rotation_are_refused(self) -> None:
        original = load_canonical_compiled_scope(self.root)
        module = sys.modules[load_canonical_compiled_scope.__module__]
        real_canonical = module._canonical_scope
        calls = 0

        def swap_manifest(root: Path, generation: int) -> dict[str, object]:
            nonlocal calls
            calls += 1
            result = real_canonical(root, generation)
            if calls == 1:
                self._write_event(cidrs=["10.11.0.0/16"])
            return result

        valid_launch = module._verified_launch_binding_sha256(self.root)
        with mock.patch.object(module, "_canonical_scope", side_effect=swap_manifest):
            with self.assertRaises(ScopeAuthorityError):
                load_canonical_compiled_scope(self.root)

        self._write_event()
        self._write_current_scope()
        with mock.patch.object(
            module,
            "_verified_launch_binding_sha256",
            side_effect=[valid_launch, "d" * 64],
        ):
            with self.assertRaises(ScopeAuthorityError):
                load_canonical_compiled_scope(self.root)

        self._write_event()
        self._write_current_scope()
        rewritten = json.dumps(self._expected_scope(), indent=2)
        (self.state / "scope.json").write_text(rewritten, encoding="utf-8")
        with self.assertRaises(ScopeAuthorityError):
            verify_canonical_compiled_scope_binding(
                self.root,
                scope_generation=original.scope_generation,
                stop_generation=original.stop_generation,
                file_sha256=original.file_sha256,
                content_sha256=original.content_sha256,
                launch_binding_sha256=original.launch_binding_sha256,
            )

        self._write_current_scope()
        rotated = load_canonical_compiled_scope(self.root)
        self._write_database(scope_generation=7, stop_generation=4)
        with self.assertRaises(ScopeAuthorityError):
            verify_canonical_compiled_scope_binding(
                self.root,
                scope_generation=rotated.scope_generation,
                stop_generation=rotated.stop_generation,
                file_sha256=rotated.file_sha256,
                content_sha256=rotated.content_sha256,
                launch_binding_sha256=rotated.launch_binding_sha256,
            )

    def test_coherent_same_generation_scope_rewrite_cannot_outlive_launch_binding(self) -> None:
        binding = load_canonical_compiled_scope(self.root)
        environment_path = self.root / ".env"
        original = environment_path.read_bytes()
        info = environment_path.stat()
        replacement = original.replace(
            b"ALLOWED_CIDRS=10.10.0.0/16",
            b"ALLOWED_CIDRS=10.10.0.0/8 ",
            1,
        )
        self.assertEqual(len(replacement), len(original))
        environment_path.write_bytes(replacement)
        os.utime(environment_path, ns=(info.st_atime_ns, info.st_mtime_ns))
        # Rebuild both derived JSON files under the unchanged SQLite generation,
        # reproducing the coherent forged-cache shape from the exact review.
        self._write_current_scope()
        with self.assertRaisesRegex(EnvironmentPolicyError, "launch_configuration_drift"):
            verify_launch_binding_integrity(self.root)
        with self.assertRaises(ScopeAuthorityError):
            load_canonical_compiled_scope(self.root)
        with self.assertRaises(ScopeAuthorityError):
            verify_canonical_compiled_scope_binding(
                self.root,
                scope_generation=binding.scope_generation,
                stop_generation=binding.stop_generation,
                file_sha256=binding.file_sha256,
                content_sha256=binding.content_sha256,
                launch_binding_sha256=binding.launch_binding_sha256,
            )

    def test_stop_and_explicit_resume_gate_effect_scope_bindings(self) -> None:
        original = load_canonical_compiled_scope(self.root)
        self._control_event("control.stop")
        with self.assertRaises(ScopeAuthorityError):
            load_canonical_compiled_scope(self.root)
        with self.assertRaises(ScopeAuthorityError):
            verify_canonical_compiled_scope_binding(
                self.root,
                scope_generation=original.scope_generation,
                stop_generation=original.stop_generation,
                file_sha256=original.file_sha256,
                content_sha256=original.content_sha256,
                launch_binding_sha256=original.launch_binding_sha256,
            )
        # A control.resume event is the only transition that re-enables a
        # fresh binding.  The old pre-stop tuple remains stale by stop gen.
        self._control_event("control.resume")
        resumed = load_canonical_compiled_scope(self.root)
        self.assertEqual(resumed.stop_generation, 4)
        self.assertEqual(resumed.launch_binding_sha256, original.launch_binding_sha256)

    def test_nonoperator_or_malformed_resume_does_not_reopen_scope_effects(self) -> None:
        self._control_event("control.stop")
        self._control_event("control.resume", actor="solver")
        with self.assertRaises(ScopeAuthorityError):
            load_canonical_compiled_scope(self.root)


class ScopeEnvironmentResolverIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        shutil.copytree(ROOKERY_ROOT / "profiles", self.root / "profiles")
        shutil.copytree(
            ROOKERY_ROOT / "adapters" / "ctfd_browser_gateway",
            self.root / "adapters" / "ctfd_browser_gateway",
        )
        (self.root / ".env").write_text(
            "\n".join(
                (
                    "PLATFORM_ADAPTER=ctfd_browser_gateway",
                    "EVENT_ID=scope-runtime",
                    "EVENT_NAME=Scope runtime",
                    "EVENT_URL=https://ctfd.fixture/event",
                    "EVENT_SCOPE_ACK=1",
                    "ALLOWED_HOSTS=ctfd.fixture",
                    "ALLOWED_PORTS=443",
                    "ALLOWED_PROTOCOLS=https",
                    "PLATFORM_HOSTS=ctfd.fixture",
                    "SCOPE_MAX_BYTES=4096",
                    "BROWSER_MODE=cdp",
                    "BROWSER_CDP_URL=http://127.0.0.1:9001",
                    "BROWSER_GATEWAY_URL=http://127.0.0.1:9003",
                    "CTFD_URL=https://ctfd.fixture",
                    "CTFD_TOKEN=fixture-only-token",
                    "ADAPTER_CONFIG_BASE_URL=https://ctfd.fixture",
                    "ADAPTER_CONFIG_SCORING_MODE=team",
                    "ADAPTER_CONFIG_EXPECTED_ACCOUNT_ID=account-7",
                    "ADAPTER_CONFIG_EXPECTED_TEAM_ID=team-9",
                    "ADAPTER_CONFIG_CSRF_PAGE_PATH=/challenges",
                    "ADAPTER_CONFIG_SESSION_LEASE_SECONDS=60",
                    "ADAPTER_CONFIG_TIMEOUT=30",
                    "ADAPTER_CONFIG_MAX_RESPONSE_BYTES=262144",
                    "ADAPTER_CONFIG_BROWSER_SUPPORT_ORIGINS=[]",
                    "",
                )
            ),
            encoding="utf-8",
        )
        resolved = resolve_manifest(self.root)
        self.assertTrue(resolved.ready)
        state = self.root / "state"
        state.mkdir()
        (state / "resolved_event.json").write_text(
            json.dumps(resolved.manifest), encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_canonical_scope_rechecks_the_full_selected_adapter_manifest(self) -> None:
        scope = _canonical_scope(self.root, generation=9)
        self.assertEqual(scope["generation"], 9)
        self.assertEqual(scope["platform_hosts"], ["ctfd.fixture"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
