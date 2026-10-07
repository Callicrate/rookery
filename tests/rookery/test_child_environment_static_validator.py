from __future__ import annotations

# ruff: noqa: E402

import ast
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

from rookery.portable.validator import (
    _adapter_extension_python_shebang_errors,
    _adapter_extension_script_root_errors,
    _child_environment_launch_errors,
    _iter_shipped_python_sources,
    _validate_adapter_extension_python_shebangs,
    _validate_child_environment_launches,
)


def write_source(root: Path, relative: str, source: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
    return path


SAFE_CHILD = textwrap.dedent(
    """
    import subprocess as sp
    from rookery.portable.environment import ChildEnvironment

    def launch(environment: ChildEnvironment):
        return sp.run(["tool"], env=environment.values)
    """
).lstrip()


class ChildEnvironmentStaticValidatorTests(unittest.TestCase):
    def test_discovers_modules_and_extensionless_python_entrypoints_deterministically(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            sources = {
                "lib/rookery/portable/core.py": SAFE_CHILD,
                "bin/root-entry": "#!/usr/bin/env python3\n" + SAFE_CHILD,
                "adapters/fixture/bin/adapter.py": SAFE_CHILD,
                "extensions/fixture/bin/extension-entry": "#!/usr/bin/python3\n"
                + SAFE_CHILD,
                "services/fixture/service.py": SAFE_CHILD,
            }
            for relative, source in sources.items():
                write_source(root, relative, source)

            errors: list[str] = []
            discovered = [relative for relative, _raw in _iter_shipped_python_sources(root, errors)]
            self.assertEqual(errors, [])
            self.assertEqual(discovered, sorted(sources))

            _validate_child_environment_launches(root, errors)
            self.assertEqual(errors, [])

    def test_all_standard_subprocess_forms_require_child_environment_values(self):
        tree = ast.parse(
            textwrap.dedent(
                """
            import subprocess as sp
            from subprocess import Popen as Start, call, check_call, check_output
            from rookery.portable.environment import ChildEnvironment

            def allowed(environment: ChildEnvironment):
                sp.run(["ok"], env=environment.values)

            sp.run(["bad"])
            Start(["bad"], env=None)
            call(["bad"], env={})
            check_call(["bad"], env=os.environ)
            check_output(["bad"], env=dict(os.environ))
                """
            )
        )
        errors = _child_environment_launch_errors(tree, "bin/standard-forms")
        self.assertEqual(
            sum("requires ChildEnvironment.values" in error for error in errors),
            2,
        )
        self.assertEqual(
            sum("forbids a whole environment mapping" in error for error in errors),
            3,
        )
        self.assertFalse(any(":5" in error for error in errors), errors)

    def test_ambient_environment_access_is_rejected_except_exact_bootstrap(self):
        tree = ast.parse(
            textwrap.dedent(
                """
            import os as system
            from os import environ as ambient

            def workspace_root():
                return system.environ.get("ROOKERY_ROOT")

            def unsafe():
                system.getenv("TOKEN")
                system.putenv("X", "Y")
                system.unsetenv("X")
                system.environ.copy()
                system.environ.update({})
                ambient["TOKEN"]
                dict(ambient)
                delayed = system.getenv
                copied = ambient
                """
            )
        )
        bootstrap_errors = _child_environment_launch_errors(
            tree, "lib/rookery/portable/cli.py"
        )
        self.assertFalse(any(":6" in error for error in bootstrap_errors), bootstrap_errors)
        self.assertGreaterEqual(
            sum("ambient environment" in error for error in bootstrap_errors), 9
        )
        non_bootstrap = _child_environment_launch_errors(tree, "bin/ambient")
        self.assertTrue(any(":6" in error for error in non_bootstrap))

    def test_duplicate_dotenv_and_raw_urlopen_are_not_waived_for_callers(self):
        tree = ast.parse(
            textwrap.dedent(
                """
            from pathlib import Path
            import urllib.request

            def read_env():
                return (Path(".") / ".env").read_text()

            urllib.request.urlopen("https://example.invalid")
                """
            )
        )
        errors = _child_environment_launch_errors(tree, "adapters/fixture/adapter.py")
        self.assertTrue(any("duplicate dotenv reader" in error for error in errors))
        self.assertTrue(any("raw urllib transfer" in error for error in errors))
        deferred = _child_environment_launch_errors(
            ast.parse("import urllib.request\nsaved = urllib.request.urlopen"),
            "adapters/fixture/adapter.py",
        )
        self.assertTrue(any("raw network callable reference" in error for error in deferred))
        shared_errors = _child_environment_launch_errors(
            ast.parse("import urllib.request\nurllib.request.urlopen('https://example.invalid')"),
            "lib/rookery/portable/scoped_transport.py",
        )
        self.assertEqual(shared_errors, [])

    def test_only_the_central_bounded_codex_probe_may_use_its_internal_mapping(self):
        tree = ast.parse(
            """
import subprocess

def _bounded_codex_probe(environment):
    return subprocess.Popen(["codex"], env=dict(environment))
"""
        )
        self.assertEqual(
            _child_environment_launch_errors(
                tree, "lib/rookery/portable/environment.py"
            ),
            [],
        )
        denied = _child_environment_launch_errors(tree, "bin/incorrect-probe")
        self.assertTrue(
            any("forbids a whole environment mapping" in error for error in denied),
            denied,
        )

    def test_adapter_extension_rookery_helpers_require_exact_isolated_shebang(self):
        safe = (
            b"#!/usr/bin/env -S python3 -I -B\n"
            b"from rookery.portable.environment import ChildEnvironment\n"
        )
        python_site_disabled = (
            b"#!/usr/bin/env -S python3 -I -S -B\n"
            b"from rookery.portable.environment import ChildEnvironment\n"
        )
        ambient = (
            b"#!/usr/bin/env python3\n"
            b"from rookery.portable.environment import ChildEnvironment\n"
        )
        standalone = b"#!/usr/bin/env python3\nimport argparse\n"
        relative = "adapters/fixture/bin/helper"
        self.assertEqual(_adapter_extension_python_shebang_errors(relative, safe), [])
        self.assertTrue(
            _adapter_extension_python_shebang_errors(relative, python_site_disabled)
        )
        self.assertTrue(_adapter_extension_python_shebang_errors(relative, ambient))
        self.assertTrue(
            _adapter_extension_python_shebang_errors(
                "extensions/fixture/bin/console-lease", standalone
            )
        )

    def test_adapter_extension_shebang_gate_discovers_unlisted_rookery_helper(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            write_source(
                root,
                "extensions/fixture/bin/unlisted-helper",
                "#!/usr/bin/env python3\n"
                "from rookery.portable.environment import ChildEnvironment\n",
            )
            errors: list[str] = []
            _validate_adapter_extension_python_shebangs(root, errors)
            self.assertTrue(
                any("exact env -S python3 -I -B shebang" in error for error in errors),
                errors,
            )
            self.assertTrue(
                any("derive one SOURCE_ROOT" in error for error in errors), errors
            )

    def test_adapter_extension_script_root_gate_rejects_cwd_library_bootstrap(self):
        relative = "extensions/fixture/bin/helper"
        safe = (
            b"#!/usr/bin/env -S python3 -I -B\n"
            b"from pathlib import Path\n"
            b"import sys\n"
            b"SOURCE_ROOT = Path(__file__).resolve().parents[3]\n"
            b"ROOT = Path.cwd()\n"
            b"sys.path.insert(0, str(SOURCE_ROOT / \"lib\"))\n"
            b"from rookery.portable.environment import ChildEnvironment\n"
            b"require_bound_runtime_workspace(ROOT)\n"
        )
        unsafe = safe.replace(
            b"SOURCE_ROOT / \"lib\"", b"ROOT / \"lib\""
        )
        self.assertEqual(_adapter_extension_script_root_errors(relative, safe), [])
        errors = _adapter_extension_script_root_errors(relative, unsafe)
        self.assertTrue(any("import only SOURCE_ROOT/lib" in error for error in errors), errors)
        self.assertTrue(any("must not select cwd/lib" in error for error in errors), errors)

        missing_binding = safe.replace(
            b"require_bound_runtime_workspace(ROOT)\n", b""
        )
        binding_errors = _adapter_extension_script_root_errors(
            relative, missing_binding
        )
        self.assertTrue(
            any("verify runtime launch binding" in error for error in binding_errors),
            binding_errors,
        )

        runtime_bin = safe + b'run_bounded_argv([str(ROOT / "bin/scope-check")])\n'
        executable_errors = _adapter_extension_script_root_errors(relative, runtime_bin)
        self.assertTrue(
            any("must not execute cwd/bin" in error for error in executable_errors),
            executable_errors,
        )

        dynamic_import_cwd_library = (
            b"#!/usr/bin/env -S python3 -I -B\n"
            b"from pathlib import Path\n"
            b"import importlib\n"
            b"import sys\n"
            b"SOURCE_ROOT = Path(__file__).resolve().parents[3]\n"
            b"ROOT = Path.cwd()\n"
            b"sys.path.insert(0, str(ROOT / \"lib\"))\n"
            b"require_bound_runtime_workspace(ROOT)\n"
            b"importlib.import_module(\"rookery.portable.environment\")\n"
        )
        dynamic_errors = _adapter_extension_script_root_errors(
            relative, dynamic_import_cwd_library
        )
        self.assertTrue(
            any("import only SOURCE_ROOT/lib" in error for error in dynamic_errors),
            dynamic_errors,
        )
        self.assertTrue(
            any("must not select cwd/lib" in error for error in dynamic_errors),
            dynamic_errors,
        )

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "mkfifo"), "requires POSIX special files")
    def test_syntax_symlink_and_special_sources_fail_deterministically(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            write_source(root, "bin/valid-entry", "#!/usr/bin/env python3\n" + SAFE_CHILD)
            write_source(root, "bin/bad.py", "def broken(:\n")
            target = write_source(root, "bin/target.py", SAFE_CHILD)
            (root / "bin" / "linked-entry").symlink_to(target)
            os.mkfifo(root / "bin" / "pipe-entry")

            first: list[str] = []
            _validate_child_environment_launches(root, first)
            second: list[str] = []
            _validate_child_environment_launches(root, second)
            self.assertEqual(first, second)
            self.assertTrue(any("syntax failed: bin/bad.py" in error for error in first))
            self.assertIn("static Python source must not be a symlink: bin/linked-entry", first)
            self.assertIn("static Python source must be a regular file: bin/pipe-entry", first)


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
