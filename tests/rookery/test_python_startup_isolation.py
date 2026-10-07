from __future__ import annotations

# ruff: noqa: E402

import ast
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from tests.rookery.support import ROOKERY_ROOT
from tests.rookery.env_fixtures import (
    configure_event_environment,
    replace_env_assignments,
)
from tests.rookery.test_preparation_and_isolation import copy_rookery

LIBRARY = ROOKERY_ROOT / "lib"
if str(LIBRARY) not in sys.path:
    sys.path.insert(0, str(LIBRARY))

from rookery.portable.environment import (  # noqa: E402
    _editable_configuration_digests,
    canonical_workspace_identity,
    immutable_source_digest,
)
from rookery.portable.validator import (  # noqa: E402
    _child_environment_launch_errors,
    _core_bin_python_shebang_errors,
    _startup_entrypoint_errors,
    _validate_core_bin_python_shebangs,
)


ORDINARY_CORE_PYTHON_HELPER_EXCLUSIONS = frozenset(
    {"build-release", "rookery-codex-launch"}
)
NON_HELP_CORE_PYTHON_HELPERS = frozenset(
    {"challenge-state", "scoring-state", "state-lint", "xorbrute.py"}
)


def has_python_shebang(path: Path) -> bool:
    lines = path.read_bytes().splitlines()
    return bool(lines) and bool(
        re.match(rb"^#![^\r\n]*\bpython(?:[0-9.]+)?(?:\s|$)", lines[0], re.I)
    )


def ordinary_core_python_helpers(root: Path) -> list[Path]:
    """Return all ordinary core Python shebang helpers without a file list."""

    return [
        path
        for path in sorted((root / "bin").iterdir())
        if path.is_file()
        and path.name not in ORDINARY_CORE_PYTHON_HELPER_EXCLUSIONS
        and has_python_shebang(path)
    ]


def poisoned_python_environment(workspace: Path) -> tuple[dict[str, str], Path]:
    """Return process-only Python startup poison plus its execution marker."""

    poison = workspace / "python-startup-poison"
    poison.mkdir()
    marker = workspace / "python-startup-executed"
    payload = (
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n"
    )
    (poison / "sitecustomize.py").write_text(payload, encoding="utf-8")
    (poison / "usercustomize.py").write_text(payload, encoding="utf-8")
    startup = poison / "startup.py"
    startup.write_text(payload, encoding="utf-8")
    user_site = (
        poison
        / "user-base"
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    user_site.mkdir(parents=True)
    (user_site / "sitecustomize.py").write_text(payload, encoding="utf-8")
    environment = dict(os.environ)
    environment.update(
        {
            "PYTHONPATH": str(poison),
            "PYTHONHOME": str(poison),
            "PYTHONSTARTUP": str(startup),
            "PYTHONUSERBASE": str(poison / "user-base"),
        }
    )
    return environment, marker


def write_fake_launch_binding(root: Path, executable: Path) -> None:
    """Bind one fake local-login Codex executable without a public bootstrap."""

    workspace = Path(canonical_workspace_identity(root))
    info = executable.stat()
    immutable_source_sha256 = immutable_source_digest(workspace)
    environment_sha256, event_manifest_sha256 = _editable_configuration_digests(workspace)
    state = root / "state"
    state.mkdir(mode=0o700, exist_ok=True)
    state.chmod(0o700)
    record = {
        "schema_version": "2",
        "workspace_identity": str(workspace),
        "immutable_source_sha256": immutable_source_sha256,
        "environment_sha256": environment_sha256,
        "event_manifest_sha256": event_manifest_sha256,
        "release_version": (root / "VERSION").read_text(encoding="utf-8").strip(),
        "baseline_sha256": "0" * 64,
        "baseline_configuration_digest": "1" * 64,
        "selected_adapter": "manual",
        "selected_extensions": [],
        "codex": {
            "path": str(executable.resolve()),
            "device": info.st_dev,
            "inode": info.st_ino,
            "size": info.st_size,
            "mtime_ns": info.st_mtime_ns,
            "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
            "version": "0.130.0",
        },
        "auth_mode": "local-login",
        "strict_config_supported": False,
    }
    binding = state / "launch_binding.json"
    binding.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
    binding.chmod(0o600)
    assert stat.S_IMODE(binding.stat().st_mode) == 0o600


class PythonStartupIsolationTests(unittest.TestCase):
    def test_every_ordinary_core_helper_uses_isolated_startup_and_only_bootstraps_root_lib(self):
        for helper in ordinary_core_python_helpers(ROOKERY_ROOT):
            relative = helper.relative_to(ROOKERY_ROOT).as_posix()
            raw = helper.read_bytes()
            self.assertEqual(_core_bin_python_shebang_errors(relative, raw), [], relative)

            source = raw.decode("utf-8")
            rookery_imports = [
                line_number
                for line_number, line in enumerate(source.splitlines(), start=1)
                if re.match(r"\s*(?:from|import)\s+rookery(?:\.|\s)", line)
            ]
            if not rookery_imports:
                continue
            insertion_lines = [
                line_number
                for line_number, line in enumerate(source.splitlines(), start=1)
                if re.match(
                    r'\s*sys\.path\.insert\(0, str\((?:ROOT|root|SCRIPT_ROOT) / "lib"\)\)',
                    line,
                )
                or re.match(r"\s*sys\.path\.insert\(0, str\(LIB\)\)", line)
            ]
            self.assertTrue(insertion_lines, f"{relative} imports Rookery without ROOT/lib bootstrap")
            self.assertLess(
                min(insertion_lines),
                min(rookery_imports),
                f"{relative} bootstraps ROOT/lib after importing Rookery",
            )
            all_insertions = [
                line_number
                for line_number, line in enumerate(source.splitlines(), start=1)
                if "sys.path.insert(" in line
            ]
            self.assertEqual(
                all_insertions,
                insertion_lines,
                f"{relative} inserts a path other than ROOT/lib",
            )

    def test_core_bin_static_gate_discovers_an_unlisted_unsafe_python_helper(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            copy_rookery(root)
            unexpected = root / "bin" / "unlisted-python-helper"
            unexpected.write_text(
                "#!/usr/bin/env python3\nprint('not isolated')\n", encoding="utf-8"
            )
            errors: list[str] = []
            _validate_core_bin_python_shebangs(root, errors)
            self.assertIn(
                "core Python entrypoint must use an isolated -I and -B shebang: "
                "bin/unlisted-python-helper",
                errors,
            )

    @unittest.skipUnless(os.name == "posix", "isolated shebang launch requires POSIX")
    def test_every_ordinary_core_helper_ignores_ambient_python_startup_and_smokes_help(self):
        with tempfile.TemporaryDirectory() as temporary:
            outer = Path(temporary)
            root = outer / "source"
            copy_rookery(root)
            environment, marker = poisoned_python_environment(outer)
            for helper in ordinary_core_python_helpers(root):
                completed = subprocess.run(
                    [str(helper), "--help"],
                    cwd=root,
                    env=environment,
                    text=True,
                    capture_output=True,
                    timeout=30,
                )
                if helper.name in NON_HELP_CORE_PYTHON_HELPERS:
                    self.assertNotEqual(completed.returncode, 124, helper.name)
                else:
                    self.assertEqual(
                        completed.returncode,
                        0,
                        f"{helper.name}: {completed.stderr}",
                    )
                self.assertFalse(marker.exists(), helper.name)

    @unittest.skipUnless(os.name == "posix", "isolated shebang launch requires POSIX")
    def test_public_and_release_entrypoints_ignore_all_ambient_python_startup_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            outer = Path(temporary)
            root = outer / "source"
            output = outer / "release-output"
            extraction = outer / "extraction"
            copy_rookery(root)
            configure_event_environment(root, "manual")
            environment, marker = poisoned_python_environment(outer)

            validated = subprocess.run(
                [str(root / "bin" / "rookery"), "validate"],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(
                validated.returncode, 0, validated.stderr + "\n" + validated.stdout
            )
            self.assertFalse(marker.exists(), validated.stdout)

            built = subprocess.run(
                [str(root / "bin" / "build-release"), "--output-dir", str(output)],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(built.returncode, 0, built.stderr)
            summary = json.loads(built.stdout)
            self.assertTrue(summary["ok"])
            self.assertFalse(marker.exists(), built.stdout)

            received = subprocess.run(
                [
                    str(root / "bin" / "build-release"),
                    "--extract-archive",
                    str(output / summary["archive"]),
                    "--manifest",
                    str(output / summary["manifest"]),
                    "--extract-dir",
                    str(extraction),
                ],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(received.returncode, 0, received.stderr)
            self.assertTrue(json.loads(received.stdout)["ok"])
            self.assertFalse(marker.exists(), received.stdout)

    @unittest.skipUnless(os.name == "posix", "isolated shebang launch requires POSIX")
    def test_run_codex_and_direct_launcher_ignore_startup_poison_before_admission(self):
        with tempfile.TemporaryDirectory() as temporary:
            outer = Path(temporary)
            root = outer / "source"
            copy_rookery(root)
            configure_event_environment(root, "manual")
            fake_bin = outer / "fake-bin"
            fake_bin.mkdir()
            trace = outer / "fake-codex-trace"
            fake = fake_bin / "codex"
            fake.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "if [ \"$1\" = --version ]; then echo 'codex-cli 0.130.0'; exit 0; fi\n"
                "if [ \"$1\" = login ]; then test \"$2\" = status; exit 0; fi\n"
                "test \"$1\" = prompt\n"
                "test -z \"${PYTHONPATH:-}\"\n"
                "test -z \"${PYTHONHOME:-}\"\n"
                f"printf '%s\\n' prompt >> {str(trace)!r}\n",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            replace_env_assignments(root, {"CODEX_AUTH_MODE": "local-login"})
            write_fake_launch_binding(root, fake)
            environment, marker = poisoned_python_environment(outer)
            environment["PATH"] = str(fake_bin) + os.pathsep + environment.get("PATH", "")

            direct = subprocess.run(
                [str(root / "bin" / "rookery-codex-launch"), "prompt"],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(direct.returncode, 2, direct.stderr)
            self.assertFalse(marker.exists(), direct.stdout)

            delegated = subprocess.run(
                [str(root / "run-codex"), "prompt"],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(delegated.returncode, 2, delegated.stderr)
            self.assertFalse(marker.exists(), delegated.stdout)
            self.assertFalse(trace.exists())

    def test_static_gate_rejects_process_aliases_dynamic_lookup_and_unsafe_startup(self):
        source = ast.parse(
            textwrap.dedent(
                """
                import asyncio as aio
                import os
                import subprocess as process
                from builtins import getattr as member
                from os import popen as open_process, system as run_system
                from rookery.portable.environment import ChildEnvironment

                async def accepted(environment: ChildEnvironment):
                    await aio.create_subprocess_exec("tool", env=environment.values)

                async def unsafe_async(environment: ChildEnvironment):
                    await aio.create_subprocess_shell("tool", env=environment.values)

                def unsafe_process(environment: ChildEnvironment, name: str):
                    process_alias = process
                    runner = member(process_alias, "run")
                    dynamic_runner = member(process, name)
                    runner(["tool"])
                    dynamic_runner(["tool"], env=environment.values)
                    run_system("tool")
                    open_process("tool")
                    member(os, "system")("tool")
                """
            )
        )
        errors = _child_environment_launch_errors(source, "bin/synthetic-entry")
        self.assertTrue(any("requires ChildEnvironment.values" in error for error in errors), errors)
        self.assertTrue(any("computed process API lookup" in error for error in errors), errors)
        self.assertTrue(any("asyncio shell process launch is forbidden" in error for error in errors), errors)
        self.assertEqual(sum("unsafe os process API" in error for error in errors), 3, errors)

        accepted = ast.parse(
            """
import asyncio as aio
import subprocess as process
from builtins import getattr as member
from rookery.portable.environment import ChildEnvironment

async def allowed(environment: ChildEnvironment):
    runner = member(process, "run")
    runner(["tool"], env=environment.values)
"""
        )
        self.assertEqual(_child_environment_launch_errors(accepted, "bin/allowed"), [])

        unsafe = _startup_entrypoint_errors(
            "bin/build-release", b"#!/usr/bin/env python3\n"
        )
        safe_direct = _startup_entrypoint_errors(
            "bin/build-release", b"#!/usr/bin/env -S python3 -I -S -B\n"
        )
        safe_shell = _startup_entrypoint_errors(
            "bin/rookery", b"#!/usr/bin/env bash\nexec python3 -I -S -B bootstrap.py\n"
        )
        unsafe_public_shell = _startup_entrypoint_errors(
            "run-codex", b"#!/usr/bin/env bash\npython3 -c 'print(1)'\n"
        )
        self.assertTrue(any("isolated -I -S shebang" in error for error in unsafe), unsafe)
        self.assertEqual(safe_direct, [])
        self.assertEqual(safe_shell, [])
        self.assertTrue(any("start Python with -I -S" in error for error in unsafe_public_shell))

        unsafe_core = _core_bin_python_shebang_errors(
            "bin/helper", b"#!/usr/bin/env python3\n"
        )
        safe_core = _core_bin_python_shebang_errors(
            "bin/helper", b"#!/usr/bin/env -S python3 -I -B\n"
        )
        safe_trusted = _core_bin_python_shebang_errors(
            "bin/build-release", b"#!/usr/bin/env -S python3 -I -S -B\n"
        )
        self.assertTrue(any("isolated -I and -B" in error for error in unsafe_core), unsafe_core)
        self.assertEqual(safe_core, [])
        self.assertEqual(safe_trusted, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
