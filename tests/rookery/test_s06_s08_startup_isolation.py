from __future__ import annotations

# ruff: noqa: E402

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.rookery.support import ROOKERY_ROOT, install_solver_ready_challenge
from tests.rookery.test_acceptance_campaign import (
    context,
    make_deployed_workspace,
    make_workspace,
)

LIBRARY = ROOKERY_ROOT / "lib"
if str(LIBRARY) not in sys.path:
    sys.path.insert(0, str(LIBRARY))

from rookery.portable.scoring import create_proposal, record_review  # noqa: E402


def poisoned_python_environment(
    workspace: Path, cwd: Path, *, include_cwd: bool = True
) -> tuple[dict[str, str], Path]:
    """Make cwd, Python paths, and customisations observable at process start."""

    poison = workspace / "python-startup-poison"
    poison.mkdir()
    marker = workspace / "python-startup-executed"
    payload = (
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n"
    )
    (poison / "sitecustomize.py").write_text(payload, encoding="utf-8")
    (poison / "usercustomize.py").write_text(payload, encoding="utf-8")
    if include_cwd:
        (cwd / "sitecustomize.py").write_text(payload, encoding="utf-8")
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


@unittest.skipUnless(os.name == "posix", "isolated shebang launch requires POSIX")
class S06S08StartupIsolationTests(unittest.TestCase):
    def test_flag_review_submit_ignores_startup_poison_and_executes_immutable_plan(self) -> None:
        workspace = make_workspace("fixture")
        try:
            root = Path(workspace.name)
            wrapper = (root / "bin" / "flag-review").read_text(encoding="utf-8")
            self.assertIn("python3 -I -S -B -c", wrapper)
            self.assertNotIn("| python3 -c", wrapper)
            manifest, _scope, store, _result = context(root, "fixture")
            install_solver_ready_challenge(root, store)
            proposal = create_proposal(
                store,
                manifest,
                objective_id="101",
                action_kind="flag",
                exact_value="FIXTURE{accepted}",
                source="analysis/s06-s08/REPORT.md",
                rationale="startup isolation execution fixture",
                actor="coordinator",
            )
            record_review(
                store,
                str(proposal["proposal_id"]),
                "approved",
                reviewer="reviewer-s06-s08",
                reason="independent fixture review",
            )

            with tempfile.TemporaryDirectory() as temporary:
                environment, marker = poisoned_python_environment(
                    Path(temporary), root
                )
                completed = subprocess.run(
                    [
                        str(root / "bin" / "flag-review"),
                        "submit",
                        str(proposal["proposal_id"]),
                    ],
                    cwd=root,
                    env=environment,
                    text=True,
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                self.assertFalse(marker.exists(), completed.stdout)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            completed_events = store.events("execution.completed")
            self.assertEqual(len(completed_events), 1, completed_events)
            plan_id = str(completed_events[0]["payload"].get("plan_id") or "")
            self.assertRegex(plan_id, r"^plan_")
            self.assertTrue((root / "state" / "execution_plans" / f"{plan_id}.json").is_file())
        finally:
            workspace.cleanup()

    def test_console_lease_selected_directly_uses_isolated_cpython_startup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            outer = Path(temporary)
            fixture = make_deployed_workspace("manual")
            self.addCleanup(fixture.cleanup)
            root = Path(fixture.name)
            helper = root / "extensions" / "guacamole" / "bin" / "console-lease"
            self.assertEqual(
                helper.read_bytes().splitlines()[0],
                b"#!/usr/bin/env -S python3 -I -B",
            )
            environment, marker = poisoned_python_environment(
                outer, root, include_cwd=False
            )
            completed = subprocess.run(
                [str(helper), "status", "--json"],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(marker.exists(), completed.stdout)


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
