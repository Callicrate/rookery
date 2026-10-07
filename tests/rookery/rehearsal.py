from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from rookery.portable.adapters import get_adapter
from rookery.portable.control import resume, stop
from rookery.portable.execution import compile_plan, execute_plan
from rookery.portable.manifest import resolve_manifest
from rookery.portable.queue import persist_schedules
from rookery.portable.registry import render_surface
from rookery.portable.scope import compile_scope
from rookery.portable.scoring import create_proposal, grant_exact, record_review
from rookery.portable.status import read_snapshot, refresh_snapshot
from tests.rookery.env_fixtures import configure_event_environment

from tests.rookery.support import (
    ROOKERY_ROOT,
    install_fixture_adapter,
    install_solver_ready_challenge,
    install_test_launch_binding,
    open_test_event_store,
)


def _copy_release_surface(source: Path, target: Path) -> None:
    for rel in [
        ".agents",
        "profiles",
        "registry",
        "agents",
        "configs",
        "docs",
        "lib",
        "bin",
    ]:
        src = source / rel
        if src.is_dir():
            shutil.copytree(src, target / rel, dirs_exist_ok=True)
    for rel in [
        ".env.example",
        "CHANGELOG.md",
        "release.json",
        "VERSION",
        "README.md",
        "AGENTS.md",
        "go",
        "run-codex",
    ]:
        shutil.copy2(source / rel, target / rel)


def run_pre_event_rehearsal(source_root: Path) -> dict[str, Any]:
    """Run a no-secret, no-network fixture event through the critical path."""
    with tempfile.TemporaryDirectory(prefix="rookery-rehearsal-") as temp:
        root = Path(temp)
        _copy_release_surface(source_root, root)
        install_fixture_adapter(root)
        configure_event_environment(
            root,
            "fixture",
            name_suffix="Offline Rehearsal",
            extra={"AUTOMATION_PERMITTED_ACTION_KINDS": "flag"},
        )
        # This rehearsal calls portable modules directly; it is not evidence
        # for the public launch gate and therefore uses a non-deployed unit
        # fixture before installing its synthetic binding.
        (root / "VERSION").unlink()
        (root / "bin" / "rookery").unlink()
        install_test_launch_binding(root)

        result = resolve_manifest(root)
        if not result.ready:
            raise RuntimeError(f"fixture rehearsal manifest not ready: {result.errors} {result.unresolved_required}")
        manifest = result.manifest
        scope = compile_scope(manifest, 1)
        store = open_test_event_store(root)
        resume(store, reason="offline rehearsal")
        surface = render_surface(root, manifest)
        adapter = get_adapter(root, manifest, scope)
        snapshot = adapter.sync()
        store.append("platform.snapshot", snapshot, actor="rehearsal")
        install_solver_ready_challenge(root, store)

        proposal = create_proposal(
            store,
            manifest,
            objective_id="101",
            action_kind="flag",
            exact_value="FIXTURE{accepted}",
            source="analysis/rehearsal/REPORT.md",
            rationale="offline scorer fixture",
            actor="rehearsal-solver",
        )
        record_review(
            store,
            proposal["proposal_id"],
            "approved",
            reviewer="rehearsal-independent-reviewer",
            reason="fixture evidence reproduced",
            verifier_report="analysis/rehearsal-verifier/REPORT.md",
        )
        grant_exact(store, proposal["proposal_id"], reason="offline rehearsal exact authorization")
        queue = persist_schedules(store, manifest)
        plan = compile_plan(store, root, manifest, scope, proposal["proposal_id"])
        execution, rc = execute_plan(store, root, manifest, scope, plan["plan_id"])
        refresh_snapshot(store, root, manifest)
        before_status = json.dumps(read_snapshot(root), sort_keys=True)
        after_status = json.dumps(read_snapshot(root), sort_keys=True)
        stop_result = stop(store, root, reason="offline rehearsal complete", wait_seconds=0.0)
        projection = store.rebuild()
        return {
            "ok": rc == 0 and execution.get("status") == "completed" and before_status == after_status,
            "manifest_ready": result.ready,
            "adapter_id": snapshot.get("adapter_id"),
            "challenge_count": len(snapshot.get("challenges", [])),
            "selected_agents": len(surface.get("agents", [])),
            "selected_tools": len(surface.get("tools", [])),
            "queue_depth": queue.get("depth", 0),
            "execution_status": execution.get("status"),
            "scorer_truth": execution.get("verdict", {}).get("scorer_truth"),
            "status_pure": before_status == after_status,
            "stop_generation": stop_result.get("generation"),
            "stopped": projection["current"].get("stopped"),
            "network_used": False,
            "credentials_used": False,
        }


def main() -> int:
    report = run_pre_event_rehearsal(ROOKERY_ROOT)
    print(json.dumps(report, indent=2))
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
