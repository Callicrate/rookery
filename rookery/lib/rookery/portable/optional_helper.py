"""Shared runtime-binding guard for optional script-derived helpers."""

from __future__ import annotations

from pathlib import Path

from .environment import EnvironmentPolicyError, verify_launch_binding_integrity


def require_bound_runtime_workspace(root: Path) -> None:
    """Verify the caller-owned workspace before any operational helper effect.

    Optional helper source and nested Rookery executables come from the
    script-derived release root.  The current working directory remains the
    workspace for state/evidence only after this value-free binding check.
    """

    try:
        verify_launch_binding_integrity(root)
    except EnvironmentPolicyError:
        # This runs before optional-helper config/state/output access.  Keep
        # the process-visible failure value-free and avoid a traceback that
        # could disclose the caller's workspace path.
        raise SystemExit("runtime_workspace_binding_invalid") from None
