from __future__ import annotations

# ruff: noqa: E402

import json
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.support import (
    ROOKERY_ROOT,
    bootstrap_public_workspace,
)
from tests.rookery.env_fixtures import (
    configure_event_environment,
    replace_env_assignments,
)

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

from rookery.portable.environment import (
    DOTENV_MAX_ASSIGNMENTS,
    DOTENV_MAX_BYTES,
    DOTENV_MAX_LINE_BYTES,
    CODEX_SHELL_POLICY_NAMES,
    ChildEnvironment,
    EnvClass,
    EnvKey,
    EnvSource,
    EnvironmentPolicyError,
    LAUNCH_BINDING_SCHEMA_VERSION,
    LaunchBinding,
    _probe_codex,
    _editable_configuration_digests,
    build_child_environment,
    canonical_workspace_identity,
    codex_launcher_environment,
    codex_launcher_main,
    codex_shell_policy_toml,
    purpose_policy,
    read_declared_environment,
    resolve_launch_gate,
    immutable_source_digest,
    write_generated_environment,
    write_prepared_environment,
)
from rookery.portable.manifest import ManifestResult, resolve_manifest


def minimal_parent(**updates: str) -> dict[str, str]:
    if os.name == "nt":
        parent = {
            "Path": os.environ.get("Path", os.defpath),
            "SystemRoot": os.environ.get("SystemRoot", r"C:\\Windows"),
            "ComSpec": os.environ.get("ComSpec", r"C:\\Windows\\System32\\cmd.exe"),
            "PATHEXT": os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD"),
            "TEMP": os.environ.get("TEMP", tempfile.gettempdir()),
            "TMP": os.environ.get("TMP", tempfile.gettempdir()),
        }
    else:
        parent = {"PATH": os.defpath}
    parent.update(updates)
    return parent


class DotenvPolicyTests(unittest.TestCase):
    def test_lf_crlf_no_final_newline_and_literal_shell_characters(self):
        declarations = (
            EnvKey("PLAIN", EnvClass.ROOKERY_CONFIG),
            EnvKey("SINGLE", EnvClass.ROOKERY_CONFIG),
            EnvKey("DOUBLE", EnvClass.ROOKERY_CONFIG),
            EnvKey("EXPORTED", EnvClass.ROOKERY_CONFIG),
        )
        body = (
            "PLAIN=$(touch marker) `touch other` # literal \\\\ value\n"
            "SINGLE=' spaced $HOME `x` '\n"
            'DOUBLE="unicode \\u2603 and \\t tab"\n'
            "export EXPORTED=a=b"
        )
        expected = None
        for newline in ("\n", "\r\n"):
            with self.subTest(newline=repr(newline)), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                (root / ".env").write_bytes(body.replace("\n", newline).encode("utf-8"))
                resolved = read_declared_environment(root, declarations, parent={})
                if expected is None:
                    expected = dict(resolved.values)
                self.assertEqual(dict(resolved.values), expected)
                self.assertEqual(resolved.values["PLAIN"], "$(touch marker) `touch other` # literal \\\\ value")
                self.assertEqual(resolved.values["SINGLE"], " spaced $HOME `x` ")
                self.assertEqual(resolved.values["DOUBLE"], "unicode ☃ and \t tab")
                self.assertFalse((root / "marker").exists())
                self.assertFalse((root / "other").exists())

    def test_declared_resolution_precedence_and_unknown_values_are_not_retained(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "state").mkdir()
            secret = "do-not-retain-this-value"
            (root / ".env").write_text(
                f"SELECTED=dotenv\nUNKNOWN={secret}\nCAPABILITY=\n", encoding="utf-8"
            )
            (root / "state/prepared.env").write_text(
                'CAPABILITY="prepared-path"\n', encoding="utf-8"
            )
            declarations = (
                EnvKey("SELECTED", EnvClass.ROOKERY_CONFIG),
                EnvKey(
                    "CAPABILITY",
                    EnvClass.CAPABILITY_PATH,
                    sources=(EnvSource.DOTENV, EnvSource.PREPARED, EnvSource.PARENT),
                ),
            )
            resolved = read_declared_environment(
                root,
                declarations,
                include_prepared=True,
                parent={"SELECTED": "parent", "CAPABILITY": "parent-path"},
            )
            self.assertEqual(resolved.values["SELECTED"], "dotenv")
            self.assertEqual(resolved.values["CAPABILITY"], "prepared-path")
            self.assertNotIn("UNKNOWN", resolved.values)
            self.assertNotIn(secret, repr(resolved))

    def test_generated_writer_round_trip_is_deterministic_json(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = root / "state/prepared.env"
            values = {"ZED": "quote \\\" slash \\\\ snow ☃", "ALPHA": " spaced "}
            write_generated_environment(path, values)
            first = path.read_bytes()
            write_generated_environment(path, values)
            self.assertEqual(path.read_bytes(), first)
            self.assertTrue(first.startswith(b'ALPHA=" spaced "\n'))
            declarations = tuple(
                EnvKey(
                    key,
                    EnvClass.CAPABILITY_PATH,
                    sources=(EnvSource.PREPARED,),
                )
                for key in values
            )
            resolved = read_declared_environment(
                root, declarations, include_prepared=True, parent={}
            )
            self.assertEqual(dict(resolved.values), values)

    def test_prepared_writer_rejects_secret_classifications(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            with self.assertRaisesRegex(EnvironmentPolicyError, "forbids class"):
                write_prepared_environment(
                    root,
                    {"TOKEN": "must-not-be-written"},
                    (EnvKey("TOKEN", EnvClass.ADAPTER_SECRET),),
                )
            self.assertFalse((root / "state/prepared.env").exists())

    def test_invalid_and_bounded_inputs_fail_without_values(self):
        cases = {
            "duplicate": b"KEY=first\nKEY=second\n",
            "malformed": b"not an assignment\n",
            "nul": b"KEY=x\0y\n",
            "invalid_utf8": b"KEY=\xff\n",
            "bare_cr": b"KEY=a\rb\n",
            "long_line": b"KEY=" + b"x" * DOTENV_MAX_LINE_BYTES,
            "too_many": b"".join(
                f"K{number}=x\n".encode() for number in range(DOTENV_MAX_ASSIGNMENTS + 1)
            ),
            "too_large": b"#" + b"x" * DOTENV_MAX_BYTES,
        }
        for label, data in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                (root / ".env").write_bytes(data)
                with self.assertRaises(EnvironmentPolicyError) as caught:
                    read_declared_environment(
                        root, (EnvKey("KEY", EnvClass.ROOKERY_CONFIG),), parent={}
                    )
                message = str(caught.exception)
                self.assertNotIn("first", message)
                self.assertNotIn("second", message)

    def test_required_key_error_is_value_free(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            with self.assertRaisesRegex(
                EnvironmentPolicyError, "required environment key missing.*NEEDED"
            ) as caught:
                read_declared_environment(
                    root,
                    (EnvKey("NEEDED", EnvClass.PROVIDER_AUTH, required=True),),
                    parent={},
                )
            self.assertNotIn("length", str(caught.exception).lower())

    def test_windows_lookup_and_duplicate_detection_are_case_insensitive(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / ".env").write_text("Mixed=one\nMIXED=two\n", encoding="utf-8")
            with (
                mock.patch("rookery.portable.environment._is_windows", return_value=True),
                self.assertRaisesRegex(EnvironmentPolicyError, "duplicate assignment"),
            ):
                read_declared_environment(
                    root, (EnvKey("MIXED", EnvClass.ROOKERY_CONFIG),), parent={}
                )


class ChildEnvironmentTests(unittest.TestCase):
    def test_minimal_child_excludes_ambient_sentinels_and_metadata_has_names_only(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            parent = minimal_parent(**{
                "LANG": "C.UTF-8",
                "HOME": "sentinel-home",
                "HTTP_PROXY": "sentinel-proxy",
                "SSH_AUTH_SOCK": "sentinel-agent",
                "CTFD_TOKEN": "sentinel-adapter",
            })
            child = build_child_environment(
                root, policy=purpose_policy("test-minimal"), parent=parent
            )
            self.assertIsInstance(child, ChildEnvironment)
            self.assertIn("Path" if os.name == "nt" else "PATH", child.values)
            self.assertIn("ROOKERY_ROOT", child.values)
            for key in ("HOME", "HTTP_PROXY", "SSH_AUTH_SOCK", "CTFD_TOKEN"):
                self.assertNotIn(key, child.values)
            metadata = child.metadata()
            serialized = json.dumps(metadata)
            self.assertNotIn("sentinel", serialized)
            self.assertNotIn("sentinel", repr(child))
            self.assertEqual(metadata["environment"]["policy"], "test-minimal")

    def test_exact_pass_name_and_owner_token_rejection(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            parent = minimal_parent(EXPLICIT="kept", OTHER="dropped")
            child = build_child_environment(
                root,
                policy=purpose_policy("explicit"),
                pass_names=("EXPLICIT",),
                parent=parent,
            )
            self.assertEqual(child.values["EXPLICIT"], "kept")
            self.assertNotIn("OTHER", child.values)
            with self.assertRaises(EnvironmentPolicyError):
                build_child_environment(
                    root,
                    policy=purpose_policy("bad-owner"),
                    pass_names=("ROOKERY_OWNER_TOKEN",),
                    parent=minimal_parent(ROOKERY_OWNER_TOKEN="x"),
                )

    def test_codex_provider_is_included_and_other_authority_is_excluded(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            home = root / "home"
            codex_home = home / ".codex"
            codex_home.mkdir(parents=True)
            (root / ".env").write_text(
                "CODEX_AUTH_MODE=environment\n"
                'CODEX_PROVIDER_ENV_KEYS=["DUMMY_PROVIDER_KEY"]\n'
                "DUMMY_PROVIDER_KEY=$(literal-provider)\n"
                "CTFD_TOKEN=adapter\n"
                "HTB_MCP_TOKEN=htb\n"
                "IMMERSIVE_COOKIES_FILE=cookies\n"
                "VPN_AUTH_FILE=vpn\n"
                "ROOKERY_OWNER_TOKEN=owner\n",
                encoding="utf-8",
            )
            parent = minimal_parent(**{
                "HOME": str(home),
                "CODEX_HOME": str(codex_home),
                "OPENAI_API_KEY": "built-in-provider",
                "SSH_AUTH_SOCK": "agent",
                "HTTP_PROXY": "proxy",
            })
            child = codex_launcher_environment(root, parent=parent)
            self.assertEqual(child.values["DUMMY_PROVIDER_KEY"], "$(literal-provider)")
            self.assertEqual(child.values["OPENAI_API_KEY"], "built-in-provider")
            self.assertEqual(child.values["HOME"], str(home))
            for key in (
                "CODEX_PROVIDER_ENV_KEYS",
                "CTFD_TOKEN",
                "HTB_MCP_TOKEN",
                "IMMERSIVE_COOKIES_FILE",
                "VPN_AUTH_FILE",
                "ROOKERY_OWNER_TOKEN",
                "SSH_AUTH_SOCK",
                "HTTP_PROXY",
            ):
                self.assertNotIn(key, child.values)

    def test_codex_shell_policy_is_names_only_and_excludes_provider(self):
        policy = codex_shell_policy_toml()
        self.assertIn('inherit = "core"', policy)
        self.assertIn("experimental_use_profile = false", policy)
        self.assertIn("ignore_default_excludes = false", policy)
        self.assertIn('"PATH" = "include"', policy)
        self.assertEqual(set(CODEX_SHELL_POLICY_NAMES), {
            line.split('"', 2)[1]
            for line in policy.splitlines()
            if line.startswith('"')
        })
        for forbidden in ("OPENAI_API_KEY", "CTFD_TOKEN", "HTTP_PROXY", "SSH_AUTH_SOCK"):
            self.assertNotIn(forbidden, policy)
        with (ROOKERY_ROOT / "configs/codex-base.toml").open("rb") as handle:
            config = tomllib.load(handle)
        # The static base works with an older CLI. The registry adds this
        # policy only after the strict-capability probe succeeds.
        self.assertNotIn("shell_environment_policy", config)

    def test_launcher_execs_with_strict_config_and_filtered_mapping(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            home = root / "home"
            home.mkdir()
            parent = minimal_parent(HOME=str(home), CTFD_TOKEN="drop")
            with (
                mock.patch("rookery.portable.environment.shutil.which", return_value="/fake/codex"),
                mock.patch(
                    "rookery.portable.environment._verify_exec_binding",
                    return_value=LaunchBinding(
                        {
                            "schema_version": "1",
                            "release_version": "2026.08.28",
                            "baseline_sha256": "a" * 64,
                            "baseline_configuration_digest": "b" * 64,
                            "selected_adapter": "manual",
                            "selected_extensions": [],
                            "codex": {
                                "path": "/fake/codex",
                                "device": 1,
                                "inode": 1,
                                "size": 1,
                                "mtime_ns": 1,
                                "version": "0.150.0",
                            },
                            "auth_mode": "local-login",
                            "strict_config_supported": True,
                        },
                        "c" * 64,
                    ),
                ),
                mock.patch(
                    "rookery.portable.environment._open_verified_codex_descriptor",
                    return_value=91,
                ),
                mock.patch("rookery.portable.environment.os.close"),
                mock.patch("rookery.portable.environment.os.execve", side_effect=RuntimeError("captured")) as execute,
                self.assertRaisesRegex(RuntimeError, "captured"),
            ):
                codex_launcher_main(["prompt"], root=root, parent=parent)
            executable, argv, environment = execute.call_args.args
            self.assertEqual(executable, "/proc/self/fd/91")
            self.assertEqual(argv, ["/proc/self/fd/91", "--strict-config", "prompt"])
            self.assertNotIn("CTFD_TOKEN", environment)
            with self.assertRaisesRegex(EnvironmentPolicyError, "overrides are forbidden"):
                codex_launcher_main(
                    ["-c", 'shell_environment_policy.inherit="all"'],
                    root=root,
                    parent=parent,
                )
            with self.assertRaisesRegex(EnvironmentPolicyError, "strict-config overrides"):
                codex_launcher_main(
                    ["--strict-config=false"], root=root, parent=parent
                )

    def test_windows_environment_block_limit_counts_utf16_bytes(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            parent = {
                "Path": os.defpath,
                "SystemRoot": r"C:\\Windows",
                "ComSpec": r"C:\\Windows\\System32\\cmd.exe",
                "PATHEXT": ".EXE;.CMD",
                "TEMP": r"C:\\Temp",
                "TMP": r"C:\\Temp",
                "BIG": "😀" * 8000,
            }
            with (
                mock.patch("rookery.portable.environment._is_windows", return_value=True),
                self.assertRaisesRegex(EnvironmentPolicyError, "block-size limit"),
            ):
                build_child_environment(
                    root,
                    policy=purpose_policy("windows-bound"),
                    pass_names=("BIG",),
                    parent=parent,
                )


class GoFailureOrderingTests(unittest.TestCase):
    def test_start_rejects_malformed_dotenv_before_runtime_effects(self):
        from rookery.portable.cli import build_parser, cmd_go

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / ".env").write_text("this is shell, not dotenv\n", encoding="utf-8")
            args = build_parser().parse_args(["go"])
            with (
                mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                mock.patch("rookery.portable.cli.private_storage_preflight") as preflight,
                mock.patch("rookery.portable.cli.ensure_runtime_dirs") as ensure_dirs,
                mock.patch("rookery.portable.cli.prepare") as prepare,
                mock.patch("sys.stderr"),
            ):
                self.assertEqual(cmd_go(args), 2)
            preflight.assert_not_called()
            ensure_dirs.assert_not_called()
            prepare.assert_not_called()

    def test_prepare_rejects_malformed_dotenv_before_runtime_effects(self):
        from rookery.portable.cli import build_parser, cmd_prepare

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / ".env").write_text("this is shell, not dotenv\n", encoding="utf-8")
            args = build_parser().parse_args(["prepare", "apply"])
            with (
                mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                mock.patch("rookery.portable.cli.private_storage_preflight") as preflight,
                mock.patch("rookery.portable.cli.ensure_runtime_dirs") as ensure_dirs,
                mock.patch("rookery.portable.cli.prepare") as prepare,
                self.assertRaises(EnvironmentPolicyError),
            ):
                cmd_prepare(args)
            preflight.assert_not_called()
            ensure_dirs.assert_not_called()
            prepare.assert_not_called()

    def test_status_does_not_parse_malformed_dotenv(self):
        from rookery.portable.cli import build_parser, cmd_go

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / ".env").write_text("bad shell syntax $(nope)\n", encoding="utf-8")
            args = build_parser().parse_args(["go", "status"])
            with (
                mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                mock.patch("builtins.print"),
            ):
                self.assertEqual(cmd_go(args), 0)


@unittest.skipIf(os.name == "nt", "Bash/permission integration runs on Linux or WSL")
class PosixLaunchIntegrationTests(unittest.TestCase):
    @staticmethod
    def copy_release(root: Path) -> None:
        ignored = shutil.ignore_patterns(
            ".env",
            "state",
            "analysis",
            "evidence",
            "submissions",
            "logs",
            "captures",
            "downloads",
            "work",
            "writeups",
            "control",
            "__pycache__",
            ".pytest_cache",
            ".ruff_cache",
            "*.pyc",
        )
        shutil.copytree(ROOKERY_ROOT, root, dirs_exist_ok=True, ignore=ignored)
        for path in (root / "go", root / "run-codex", root / "bin/rookery-codex-launch"):
            path.chmod(path.stat().st_mode | 0o111)

    @staticmethod
    def make_non_deployed_unit_root(root: Path) -> None:
        """Keep direct launcher fixtures out of the public binding contract."""

        (root / "VERSION").unlink()
        (root / "bin" / "rookery").unlink()

    @staticmethod
    def _write_exec_binding(
        root: Path, executable: Path, *, version: str, strict: bool, auth_mode: str
    ) -> None:
        state = root / "state"
        state.mkdir(mode=0o700)
        state.chmod(0o700)
        info = executable.stat()
        workspace = Path(canonical_workspace_identity(root))
        immutable_source_sha256 = immutable_source_digest(workspace)
        manifest = resolve_manifest(workspace).manifest
        environment_sha256, resolved_manifest_sha256 = _editable_configuration_digests(
            workspace
        )
        record = {
            "schema_version": LAUNCH_BINDING_SCHEMA_VERSION,
            "workspace_identity": str(workspace),
            "immutable_source_sha256": immutable_source_sha256,
            "environment_sha256": environment_sha256,
            "resolved_manifest_sha256": resolved_manifest_sha256,
            "release_version": (
                (root / "VERSION").read_text(encoding="utf-8").strip()
                if (root / "VERSION").is_file()
                else "test-only"
            ),
            "baseline_sha256": "0" * 64,
            "baseline_configuration_digest": "1" * 64,
            "measurement_contract": {
                "queue_automation_enabled": bool(
                    manifest.get("queue", {}).get("automation_enabled", False)
                ),
                "provider_fields": {
                    name: {"availability": "unavailable"}
                    for name in ("queue", "tokens", "usage")
                },
            },
            "selected_adapter": str(manifest["adapter"]["id"]),
            "selected_extensions": list(
                manifest.get("surface", {}).get("extensions", [])
            ),
            "codex": {
                "path": str(executable.resolve()),
                "device": info.st_dev,
                "inode": info.st_ino,
                "size": info.st_size,
                "mtime_ns": info.st_mtime_ns,
                "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                "version": version,
            },
            "auth_mode": auth_mode,
            "strict_config_supported": strict,
        }
        binding = state / "launch_binding.json"
        binding.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
        binding.chmod(0o600)
        assert stat.S_IMODE(binding.stat().st_mode) == 0o600

    def test_fake_codex_lf_crlf_and_literal_shell_values(self):
        literal = "$(touch marker) `touch other` # literal"
        for newline in ("\n", "\r\n"):
            with self.subTest(newline=repr(newline)), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                self.copy_release(root)
                self.make_non_deployed_unit_root(root)
                fake_bin = root / "fake-bin"
                fake_bin.mkdir()
                fake = fake_bin / "codex"
                fake.write_text(
                    "#!/usr/bin/env bash\n"
                    "set -euo pipefail\n"
                    "if [ \"$1\" = --version ]; then echo 'codex-cli 0.150.0'; exit 0; fi\n"
                    "if [ \"$1\" = --strict-config ] && [ \"$2\" = --version ]; then exit 0; fi\n"
                    "if [ \"$1\" = --strict-config ] && [ \"$2\" = login ]; then test \"$3\" = status; exit 0; fi\n"
                    "if [ \"$1\" = login ]; then test \"$2\" = status; exit 0; fi\n"
                    "test \"$1\" = --strict-config\n"
                    "test \"$2\" = prompt\n"
                    "test -z \"${CTFD_TOKEN:-}\"\n"
                    "test -z \"${SSH_AUTH_SOCK:-}\"\n"
                    "printf '%s' \"$DUMMY_PROVIDER_KEY\" > fake-codex-value.txt\n",
                    encoding="utf-8",
                )
                fake.chmod(0o755)
                configure_event_environment(root, "manual")
                replace_env_assignments(
                    root,
                    {
                        "CODEX_AUTH_MODE": "environment",
                        "CODEX_PROVIDER_ENV_KEYS": '["DUMMY_PROVIDER_KEY"]',
                        "DUMMY_PROVIDER_KEY": literal,
                    },
                )
                dotenv = (root / ".env").read_text(encoding="utf-8")
                (root / ".env").write_bytes(
                    dotenv.replace("\n", newline).encode("utf-8")
                )
                self._write_exec_binding(
                    root,
                    fake,
                    version="0.150.0",
                    strict=True,
                    auth_mode="environment",
                )
                environment = {
                    **os.environ,
                    "PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", ""),
                    "CTFD_TOKEN": "adapter-secret",
                    "SSH_AUTH_SOCK": "agent-capability",
                }
                result = subprocess.run(
                    [str(root / "run-codex"), "prompt"],
                    cwd=root,
                    env=environment,
                    text=True,
                    capture_output=True,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((root / "fake-codex-value.txt").read_text(), literal)
                self.assertFalse((root / "marker").exists())
                self.assertFalse((root / "other").exists())

    def test_fake_0130_local_login_omits_strict_config(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.copy_release(root)
            self.make_non_deployed_unit_root(root)
            fake_temp = tempfile.TemporaryDirectory()
            fake_bin = Path(fake_temp.name) / "fake-bin"
            fake_bin.mkdir()
            fake = fake_bin / "codex"
            fake.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "if [ \"$1\" = --version ]; then echo 'codex-cli 0.130.0'; exit 0; fi\n"
                "if [ \"$1\" = login ]; then test \"$2\" = status; exit 0; fi\n"
                "if [ \"$1\" = --strict-config ]; then exit 2; fi\n"
                "test \"$1\" = prompt\n"
                "test -z \"${OPENAI_API_KEY:-}\"\n"
                "printf ok > fake-codex-0130.txt\n",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            configure_event_environment(root, "manual")
            replace_env_assignments(root, {"CODEX_AUTH_MODE": "local-login"})
            self._write_exec_binding(
                root,
                fake,
                version="0.130.0",
                strict=False,
                auth_mode="local-login",
            )
            result = subprocess.run(
                [str(root / "run-codex"), "prompt"],
                cwd=root,
                env={
                    **os.environ,
                    "PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", ""),
                    "OPENAI_API_KEY": "must-not-reach-codex",
                },
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / "fake-codex-0130.txt").read_text(), "ok")

    def test_status_and_stop_survive_malformed_live_dotenv(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.copy_release(root)
            configure_event_environment(
                root,
                "manual",
                name_suffix="Status Fixture",
                extra={
                    "EVENT_ID": "status-fixture",
                    "ALLOWED_HOSTS": "fixture.invalid",
                    "ALLOWED_CIDRS": "",
                    "ALLOWED_PORTS": "443",
                    "ALLOWED_PROTOCOLS": "https",
                    "ALLOWED_FILE_ORIGINS": "fixture://*",
                    "PLATFORM_HOSTS": "",
                    "SCOPE_MAX_BYTES": "1024",
                },
            )
            fake_temp = tempfile.TemporaryDirectory()
            fake_bin = Path(fake_temp.name) / "fake-bin"
            fake_bin.mkdir()
            fake = fake_bin / "codex"
            fake.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "if [ \"$1\" = --version ]; then echo 'codex-cli 0.150.0'; exit 0; fi\n"
                "if [ \"$1\" = --strict-config ] && [ \"$2\" = --version ]; then exit 0; fi\n"
                "if [ \"$1\" = doctor ]; then printf '%s\\n' '{\"checks\":{\"config.load\":{\"status\":\"ok\"}}}'; exit 0; fi\n"
                "if [ \"$1\" = login ] && [ \"$2\" = status ]; then exit 0; fi\n"
                "exit 2\n",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            launch_environment = {
                **os.environ,
                "PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", ""),
            }
            bootstrap = bootstrap_public_workspace(
                root, environment=launch_environment
            )
            (root / ".env").write_text("malformed $(touch should-not-run)\n", encoding="utf-8")
            status = subprocess.run(
                [str(root / "go"), "status"],
                cwd=root,
                env=bootstrap.environment,
                text=True,
                capture_output=True,
                timeout=30,
            )
            stopped = subprocess.run(
                [str(root / "go"), "stop"],
                cwd=root,
                env=bootstrap.environment,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(status.returncode, 0, status.stderr)
            self.assertEqual(stopped.returncode, 0, stopped.stderr)
            self.assertIn('"generation"', stopped.stdout)
            self.assertIn('"emergency_stop": true', stopped.stdout)
            self.assertFalse((root / "should-not-run").exists())
            bootstrap.cleanup()
            fake_temp.cleanup()

    def test_stop_uses_canonical_loader_without_parsing_live_dotenv(self):
        from rookery.portable.cli import build_parser, cmd_go
        from rookery.portable.manifest import resolve_manifest

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / ".env").write_text("bad shell syntax $(nope)\n", encoding="utf-8")
            result = resolve_manifest(ROOKERY_ROOT, env={})
            store = mock.Mock()
            args = build_parser().parse_args(["go", "stop"])
            with (
                mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                mock.patch("rookery.portable.cli.private_storage_preflight"),
                mock.patch("rookery.portable.cli.ensure_runtime_dirs"),
                mock.patch(
                    "rookery.portable.cli._load_stop_context",
                    return_value=(result.manifest, {}, store, result),
                ),
                mock.patch("rookery.portable.cli.stop", return_value={"generation": 2}),
                mock.patch("rookery.portable.cli.write_stop_prompt"),
                mock.patch("rookery.portable.cli.create_lessons_document", return_value="lessons.md"),
                mock.patch("rookery.portable.cli.check_writeups", return_value={}),
                mock.patch("rookery.portable.cli.refresh_snapshot"),
                mock.patch("builtins.print"),
            ):
                self.assertEqual(cmd_go(args), 0)

class LaunchGateTests(unittest.TestCase):
    @staticmethod
    def _ready_manifest() -> dict[str, object]:
        return {
            "adapter": {"id": "manual", "config": {}},
            "capabilities": {"required": []},
            "surface": {"extensions": []},
        }

    @staticmethod
    def _verified_baseline() -> dict[str, object]:
        """Value-free result returned by the strict baseline verifier."""

        return {
            "sha256": "a" * 64,
            "configuration_digest": "b" * 64,
            "release_version": "2026.08.28",
            "measurement_contract": {
                "queue_automation_enabled": False,
                "provider_fields": {
                    "queue": {"availability": "unavailable"},
                    "tokens": {"availability": "unavailable"},
                    "usage": {"availability": "unavailable"},
                },
            },
        }

    def test_gate_is_pure_until_binding_publication(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            marker = root / "shell-side-effect"
            (root / ".env").write_text(
                "ROOKERY_MEASUREMENT_BASELINE_PATH=../baseline.json\r\n"
                f"IGNORED_LITERAL=$(touch {marker})\r\n",
                encoding="utf-8",
                newline="",
            )
            result = ManifestResult(self._ready_manifest(), (), (), ())
            with (
                mock.patch(
                    "rookery.portable.manifest.resolve_manifest", return_value=result
                ),
                mock.patch(
                    "rookery.portable.baseline.verify_measurement_baseline",
                    return_value=self._verified_baseline(),
                ),
                mock.patch(
                    "rookery.portable.environment._probe_codex",
                    return_value=(
                        "/fake/codex",
                        {
                            "path": "/fake/codex",
                            "device": 1,
                            "inode": 2,
                            "size": 3,
                            "mtime_ns": 4,
                        },
                        "0.130.0",
                        False,
                    ),
                ),
            ):
                gate = resolve_launch_gate(root, parent=minimal_parent())
            self.assertEqual(gate.auth_mode, "local-login")
            self.assertFalse(gate.strict_config_supported)
            self.assertEqual(
                gate.measurement_contract["provider_fields"]["queue"]["availability"],
                "unavailable",
            )
            self.assertFalse((root / "state").exists())
            self.assertFalse(marker.exists())

    def test_environment_auth_requires_strict_before_any_write(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / ".env").write_text(
                "ROOKERY_MEASUREMENT_BASELINE_PATH=../baseline.json\n"
                "CODEX_AUTH_MODE=environment\n",
                encoding="utf-8",
            )
            result = ManifestResult(self._ready_manifest(), (), (), ())
            with (
                mock.patch(
                    "rookery.portable.manifest.resolve_manifest", return_value=result
                ),
                mock.patch(
                    "rookery.portable.baseline.verify_measurement_baseline",
                    return_value=self._verified_baseline(),
                ),
                mock.patch(
                    "rookery.portable.environment._probe_codex",
                    return_value=(
                        "/fake/codex",
                        {
                            "path": "/fake/codex",
                            "device": 1,
                            "inode": 2,
                            "size": 3,
                            "mtime_ns": 4,
                        },
                        "0.130.0",
                        False,
                    ),
                ),
                self.assertRaisesRegex(
                    EnvironmentPolicyError, "requires_strict_config"
                ),
            ):
                resolve_launch_gate(root, parent=minimal_parent())
            self.assertFalse((root / "state").exists())

    def test_codex_probe_keeps_login_and_strict_capability_separate(self):
        child = ChildEnvironment({"PATH": os.defpath}, "fixture", ())
        with (
            mock.patch(
                "rookery.portable.environment._absolute_codex_executable",
                return_value=(
                    "/fake/codex",
                    {
                        "path": "/fake/codex",
                        "device": 1,
                        "inode": 2,
                        "size": 3,
                        "mtime_ns": 4,
                    },
                ),
            ),
            mock.patch(
                "rookery.portable.environment._bounded_codex_probe",
                side_effect=[
                    (0, b"codex-cli 0.130.0\n"),
                    (2, b"unknown option --strict-config\n"),
                    (0, b"cached login ready\n"),
                ],
            ) as probe,
        ):
            _executable, _identity, version, strict = _probe_codex(
                Path.cwd(), child
            )
        self.assertEqual(version, "0.130.0")
        self.assertFalse(strict)
        self.assertEqual(
            [call.args[1] for call in probe.call_args_list],
            [
                ("--version",),
                ("--strict-config", "--version"),
                ("login", "status"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
