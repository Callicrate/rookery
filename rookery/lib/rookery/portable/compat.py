from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Collection

from .environment import minimal_child_environment

PLAN_ID = re.compile(r"plan_[A-Za-z0-9]+")


def execute_plan_alias(
    root: Path,
    plan_id: str,
    *,
    allowed_actions: Collection[str],
    adapter_id: str | None = None,
    timeout: int = 3600,
) -> int:
    """Execute an existing canonical plan through the Rookery control CLI."""

    if not PLAN_ID.fullmatch(plan_id):
        raise ValueError("a canonical plan ID is required")
    plan_path = root / "state" / "execution_plans" / f"{plan_id}.json"
    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"execution plan not found: {plan_id}") from exc
    if plan.get("semantic_action") not in allowed_actions:
        raise ValueError(
            f"plan action is not supported by this alias: {plan.get('semantic_action')}"
        )
    if adapter_id is not None and plan.get("adapter_id") != adapter_id:
        raise ValueError(f"plan adapter must be {adapter_id}")
    command = [str(root / "bin" / "rookery"), "score", "execute", plan_id]
    child_environment = minimal_child_environment(
        root, policy_name="compat-plan-execution"
    )
    try:
        return subprocess.run(
            command,
            cwd=root,
            timeout=timeout,
            env=child_environment.values,
        ).returncode
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"execution plan timed out after {timeout} seconds: {plan_id}"
        ) from exc
