from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ROOKERY_ROOT = REPOSITORY_ROOT / "rookery"
TESTS_ROOT = REPOSITORY_ROOT / "tests"
FIXTURE_ADAPTER_ROOT = TESTS_ROOT / "fixtures" / "adapters" / "fixture"


def install_solver_ready_challenge(
    root: Path,
    store,
    challenge_id: str = "101",
    *,
    adapter_id: str = "fixture",
) -> dict[str, object]:
    """Install one immutable, verified challenge-intake fixture."""

    intake = root / "captures" / "test-intake" / challenge_id
    intake.mkdir(parents=True, exist_ok=True)
    detail = intake / "detail.json"
    detail_bytes = json.dumps(
        {"id": challenge_id, "files": []},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    detail.write_bytes(detail_bytes)
    if os.name == "posix":
        detail.chmod(0o600)
    row: dict[str, object] = {
        "id": challenge_id,
        "title": f"Fixture challenge {challenge_id}",
        "classification": "untriaged",
        "solved": False,
        "files": [],
        "detail_path": str(detail.relative_to(root)).replace("\\", "/"),
        "detail_sha256": hashlib.sha256(detail_bytes).hexdigest(),
        "detail_bytes": len(detail_bytes),
        "captured_files": [],
        "expected_file_count": 0,
        "captured_file_count": 0,
        "ingested_at": "2026-10-02T00:00:00Z",
        "intake_state": "complete",
        "intake_missing_material": [],
        "resources_truncated": False,
        "resources_complete": True,
    }
    store.append(
        "platform.snapshot",
        {"adapter_id": adapter_id, "challenges": [row]},
        actor="fixture",
    )
    return row


def render_handoff_report(
    *,
    status: str = "technical_negative",
    source_handoff: str = "none",
    source_report_sha256: str = "none",
    observed_result: str = "The bounded fixture route produced a useful negative.",
    route_key: str = "fixture-route",
    proof_gap: str = "One independent fixture route remains untested.",
    discriminating_test: str = "Compare the alternate fixture representation once.",
    next_step_or_return_trigger: str = "Queue the alternate bounded fixture route.",
    evidence_paths: tuple[str, ...] = ("analysis/fixture/evidence.txt",),
    command_artifact_paths: tuple[str, ...] = ("analysis/fixture/commands.txt",),
    blocker: str = "none",
    cleanup_jobs: str = "no background jobs",
    evidence_body: str = "The exact fixture evidence remains at the declared private path.",
    commands_body: str = "The bounded fixture command record is listed above.",
) -> str:
    """Render one valid canonical worker handoff report for test fixtures."""

    return "\n".join(
        (
            "# Worker report",
            "",
            "## Handoff",
            f"Status: {status}",
            f"Source handoff: {source_handoff}",
            f"Source report SHA-256: {source_report_sha256}",
            f"Observed result: {observed_result}",
            f"Route key: {route_key}",
            f"Proof gap: {proof_gap}",
            f"Discriminating test: {discriminating_test}",
            f"Next step or return trigger: {next_step_or_return_trigger}",
            "Evidence paths: "
            + json.dumps(list(evidence_paths), separators=(",", ":")),
            "Command/artifact paths: "
            + json.dumps(list(command_artifact_paths), separators=(",", ":")),
            f"Blocker: {blocker}",
            f"Cleanup/jobs: {cleanup_jobs}",
            "",
            "## Evidence",
            evidence_body,
            "",
            "## Commands",
            commands_body,
            "",
        )
    )


def install_test_launch_binding(
    root: Path, *, release_version: str | None = None
) -> Path:
    """Install an explicit structural binding for a non-deployed test workspace.

    It hashes copied source/configuration and uses the production binding
    schema.  It is deliberately not a substitute for the public first-write
    gate: a root that has both deployed markers must use
    :func:`bootstrap_public_workspace` instead.
    """

    root = Path(root)
    if (root / "VERSION").is_file() and (root / "bin" / "rookery").is_file():
        raise RuntimeError(
            "synthetic launch bindings are only valid for non-deployed test roots; "
            "use bootstrap_public_workspace"
        )

    version = release_version
    if version is None:
        version_file = root / "VERSION"
        version = (
            version_file.read_text(encoding="utf-8").strip()
            if version_file.is_file()
            else "test-only"
        )
    from rookery.portable.environment import (
        LAUNCH_BINDING_SCHEMA_VERSION,
        _editable_configuration_digests,
        canonical_workspace_identity,
        immutable_source_digest,
    )
    from rookery.portable.manifest import resolve_manifest

    workspace = Path(canonical_workspace_identity(root))
    immutable_source_sha256 = immutable_source_digest(workspace)
    result = resolve_manifest(workspace, parent={})
    if not result.ready:
        raise RuntimeError("test launch binding requires a ready .env")
    environment_sha256, resolved_manifest_sha256 = _editable_configuration_digests(
        workspace, result.manifest
    )
    state = root / "state"
    state.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        state.chmod(0o700)
    record = {
        "schema_version": LAUNCH_BINDING_SCHEMA_VERSION,
        "workspace_identity": str(workspace),
        "immutable_source_sha256": immutable_source_sha256,
        "environment_sha256": environment_sha256,
        "resolved_manifest_sha256": resolved_manifest_sha256,
        "release_version": version,
        "baseline_sha256": "0" * 64,
        "baseline_configuration_digest": "1" * 64,
        "measurement_contract": {
            "queue_automation_enabled": bool(
                result.manifest.get("queue", {}).get("automation_enabled", False)
            ),
            "provider_fields": {
                name: {"availability": "unavailable"}
                for name in ("queue", "tokens", "usage")
            },
        },
        "selected_adapter": str(result.manifest["adapter"]["id"]),
        "selected_extensions": list(result.manifest.get("surface", {}).get("extensions", [])),
        "codex": {
            "path": "/test/codex",
            "device": 0,
            "inode": 0,
            "size": 0,
            "mtime_ns": 0,
            "sha256": "2" * 64,
            "version": "0.150.0",
        },
        "auth_mode": "local-login",
        "strict_config_supported": True,
    }
    data = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    target = state / "launch_binding.json"
    target.write_bytes(data)
    if os.name == "posix":
        target.chmod(0o600)
    return target


def open_test_event_store(root: Path):
    """Open a test fixture store with its explicit structural binding."""

    from rookery.portable.environment import read_launch_binding
    from rookery.portable.store import EventStore

    return EventStore(root, launch_binding=read_launch_binding(root))


def copy_non_deployed_rookery(root: Path) -> None:
    """Copy a structural fixture without the public deployment marker.

    These fixtures may exercise shipped helper commands, but they cannot make a
    public-launch claim. The caller must write a complete private `.env` and
    call :func:`rebind_test_workspace` before it opens an event store or starts
    a bound command. This preserves the production rule that an unresolved
    configuration never receives a launch binding.
    """

    root = Path(root)
    excluded = {
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
        "START_PROMPT.md",
        "STOP_PROMPT.md",
        "NEW_CTF_SETUP.md",
        "PREPARATION.md",
        "ACTIVE_SURFACE.md",
        "STATUS.md",
        "FINDINGS.md",
        "FLAGS.md",
        "DEAD_PATHS.md",
        ".ruff_cache",
        ".pytest_cache",
        "VERSION",
    }
    for child in ROOKERY_ROOT.iterdir():
        if child.name in excluded:
            continue
        target = root / child.name
        if child.is_dir():
            shutil.copytree(
                child,
                target,
                symlinks=True,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
        else:
            shutil.copy2(child, target)
    shutil.copyfile(root / ".env.example", root / ".env")
    for path in [root / "go", root / "run-codex", *(root / "bin").glob("*")]:
        if path.is_file():
            path.chmod(path.stat().st_mode | 0o111)


def rebind_test_workspace(root: Path) -> None:
    """Rebind a deliberately edited, non-deployed fixture before test events."""

    root = Path(root)
    # Check before removing state.  A deployed test root must not lose state as
    # a side effect of rejecting a synthetic binding request.
    if (root / "VERSION").is_file() and (root / "bin" / "rookery").is_file():
        raise RuntimeError(
            "synthetic launch bindings are only valid for non-deployed test roots; "
            "use bootstrap_public_workspace"
        )

    state = root / "state"
    if state.exists():
        shutil.rmtree(state)
    install_test_launch_binding(root)
    open_test_event_store(root)


@dataclass
class PublicWorkspaceBootstrap:
    """Hermetic external baseline retained for a deployed public test root."""

    temporary: tempfile.TemporaryDirectory[str]
    baseline_path: Path
    environment: dict[str, str]

    def cleanup(self) -> None:
        self.temporary.cleanup()


def _replace_dotenv_assignment(path: Path, key: str, value: str) -> None:
    """Replace one test-only dotenv assignment without adding a duplicate."""

    if "\n" in value or "\r" in value:
        raise RuntimeError("test dotenv value must be one line")
    prefix = key + "="
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    replacements = 0
    updated: list[str] = []
    for line in lines:
        if line.startswith(prefix):
            replacements += 1
            ending = "\r\n" if line.endswith("\r\n") else "\n"
            updated.append(prefix + value + ending)
        else:
            updated.append(line)
    if replacements != 1:
        raise RuntimeError("test dotenv assignment is missing or duplicate")
    path.write_text("".join(updated), encoding="utf-8", newline="")


def bootstrap_public_workspace(
    root: Path,
    *,
    environment: Mapping[str, str],
    timeout: float = 60.0,
) -> PublicWorkspaceBootstrap:
    """Create a real baseline and execute Rookery's public first preflight.

    The caller supplies a hermetic Codex executable through ``environment``.
    The builder replaces live ``.env`` with the reviewed template, so no
    operator values are copied into the archive, manifest, or error output.
    """

    from rookery.portable.baseline import write_measurement_baseline
    from rookery.portable.release import build_release
    from rookery.portable.validator import validate_tree

    if not (root / "VERSION").is_file() or not (root / "bin" / "rookery").is_file():
        raise RuntimeError("public bootstrap requires a deployed Rookery root")
    if (root / "state").exists():
        raise RuntimeError("public bootstrap requires a state-free Rookery root")
    source_report = validate_tree(
        root, strict_release=True, source_checkout=True
    )
    if not source_report.get("ok"):
        raise RuntimeError("public bootstrap source validation failed")
    temporary = tempfile.TemporaryDirectory(prefix="rookery-public-bootstrap-")
    external = Path(temporary.name)
    try:
        artifacts = external / "artifacts"
        baseline_path = external / "measurement-baseline.json"
        _replace_dotenv_assignment(
            root / ".env", "ROOKERY_MEASUREMENT_BASELINE_PATH", str(baseline_path)
        )
        installed_report = validate_tree(root, strict_release=True)
        if not installed_report.get("ok"):
            raise RuntimeError("public bootstrap installed validation failed")
        summary = build_release(root, artifacts)
        write_measurement_baseline(
            root,
            artifacts / str(summary["archive"]),
            artifacts / str(summary["manifest"]),
            baseline_path,
        )
        child_environment = dict(environment)
        child_environment.pop("ROOKERY_MEASUREMENT_BASELINE_PATH", None)
        child_environment.setdefault("PYTHONDONTWRITEBYTECODE", "1")
        completed = subprocess.run(
            [str(root / "bin" / "rookery"), "go"],
            cwd=root,
            env=child_environment,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError("public bootstrap preflight failed")
        return PublicWorkspaceBootstrap(temporary, baseline_path, child_environment)
    except BaseException:
        temporary.cleanup()
        raise


def install_fixture_adapter(root: Path) -> None:
    shutil.copytree(FIXTURE_ADAPTER_ROOT, root / "adapters" / "fixture", dirs_exist_ok=True)
