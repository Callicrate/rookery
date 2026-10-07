from __future__ import annotations

# ruff: noqa: E402

import copy
import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.telemetry import build_report
from rookery.portable import telemetry as telemetry_module
from rookery.portable import telemetry_compare as telemetry_compare_module
from rookery.portable.telemetry_compare import (
    TelemetryComparisonError,
    compare_runtime_roots,
    main as compare_main,
)
from rookery.portable.util import canonical_json


def event(
    sequence: int,
    event_id: str,
    event_type: str,
    payload: dict[str, object] | None = None,
    *,
    second: int | None = None,
    actor: str = "fixture",
) -> dict[str, object]:
    return {
        "seq": sequence,
        "event_id": event_id,
        "event_type": event_type,
        "created_at": f"2026-08-28T00:00:{sequence if second is None else second:02d}Z",
        "generation": 0,
        "actor": actor,
        "payload": payload or {},
    }


def write_events(root: Path, rows: list[dict[str, object]]) -> None:
    state = root / "state"
    state.mkdir(parents=True, exist_ok=True)
    (state / "events.jsonl").write_text(
        "".join(canonical_json(row) + "\n" for row in rows), encoding="utf-8"
    )
    sqlite_path = state / "events.sqlite3"
    sqlite_path.unlink(missing_ok=True)
    connection = sqlite3.connect(sqlite_path)
    try:
        connection.execute(
            "CREATE TABLE events (seq INTEGER, event_id TEXT, event_type TEXT, "
            "created_at TEXT, generation INTEGER, actor TEXT, payload_json TEXT)"
        )
        for row in rows:
            connection.execute(
                "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    row["seq"],
                    row["event_id"],
                    row["event_type"],
                    row["created_at"],
                    row["generation"],
                    row["actor"],
                    canonical_json(row["payload"]),
                ),
            )
        connection.commit()
    finally:
        connection.close()


def runtime_snapshot(root: Path) -> dict[str, tuple[bytes, int, int]]:
    return {
        path.relative_to(root).as_posix(): (
            path.read_bytes(),
            stat.S_IMODE(path.stat().st_mode),
            path.stat().st_mtime_ns,
        )
        for path in root.rglob("*")
        if path.is_file()
    }


def remap_evidence_paths(rows: list[dict[str, object]], source_root: str) -> None:
    for row in rows:
        payload = row["payload"]
        assert isinstance(payload, dict)
        if row["event_type"] == "execution.planned":
            payload["evidence_paths"] = [source_root + "/evidence/plan.txt"]
            payload["plan_sha256"] = hashlib.sha256(
                canonical_json(
                    {
                        key: value
                        for key, value in payload.items()
                        if key not in {"plan_path", "plan_sha256"}
                    }
                ).encode("utf-8")
            ).hexdigest()
        elif row["event_type"] == "execution.completed":
            payload["response_path"] = source_root + "/evidence/response.json"
            payload["evidence_root"] = source_root + "/evidence"


def write_command(root: Path) -> None:
    directory = root / "logs" / "commands" / "command-one"
    directory.mkdir(parents=True)
    stdout = b"fixture command output\n"
    stderr = b""
    (directory / "stdout.log").write_bytes(stdout)
    (directory / "stderr.log").write_bytes(stderr)
    command = ["fixture-command", "--safe"]
    meta = {
        "schema_version": "2",
        "command_id": "command-one",
        "complete": True,
        "command": command,
        "argv_sha256": hashlib.sha256(canonical_json(command).encode("utf-8")).hexdigest(),
        "exit_code": 0,
        "termination": "exited",
        "stdout_path": "logs/commands/command-one/stdout.log",
        "stderr_path": "logs/commands/command-one/stderr.log",
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
    }
    digest = {
        "schema_version": "2",
        "complete": True,
        "byte_count": len(stdout),
        "sha256": meta["stdout_sha256"],
        "stderr": {"byte_count": 0, "sha256": meta["stderr_sha256"]},
    }
    (directory / "meta.json").write_text(canonical_json(meta), encoding="utf-8")
    (directory / "digest.json").write_text(canonical_json(digest), encoding="utf-8")


def write_evidence_manifest(
    root: Path,
    plan_ids: tuple[str, ...] = ("plan-one",),
    *,
    no_submit_plans: set[str] | None = None,
    no_submit_evidence_roots: dict[str, str] | None = None,
) -> None:
    no_submit = no_submit_plans or set()
    no_submit_roots = no_submit_evidence_roots or {}
    files = []
    file_paths = {"evidence/plan.txt", "evidence/response.json"}
    file_paths.update(path for path in no_submit_roots.values() if path)
    for relative in sorted(file_paths):
        data = (root / relative).read_bytes()
        files.append(
            {
                "path": relative,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    references = []
    for plan_id in plan_ids:
        references.append(
            {
                "required": True,
                "status": "present_file",
                "kind": "plan_evidence",
                "plan_id": plan_id,
                "path": "evidence/plan.txt",
            }
        )
        if plan_id not in no_submit:
            references.append(
                {
                    "required": True,
                    "status": "present_file",
                    "kind": "response",
                    "plan_id": plan_id,
                    "path": "evidence/response.json",
                }
            )
        evidence_root = (
            no_submit_roots.get(plan_id, "evidence/plan.txt")
            if plan_id in no_submit
            else "evidence"
        )
        if evidence_root:
            references.append(
                {
                    "required": True,
                    "status": "present_file"
                    if plan_id in no_submit
                    else "present_directory",
                    "kind": "execution_evidence",
                    "plan_id": plan_id,
                    "path": evidence_root,
                }
            )
    statuses = {
        status: sum(reference["status"] == status for reference in references)
        for status in ("empty", "missing", "present_directory", "present_file", "rejected")
    }
    manifest = {
        "schema_version": "3",
        "complete": True,
        "truncated": False,
        "file_count": len(files),
        "total_bytes": sum(row["bytes"] for row in files),
        "files": files,
        "required_reference_count": len(references),
        "required_reference_counts": statuses,
        "references": references,
    }
    (root / "evidence" / "latest-manifest.json").write_text(
        canonical_json(manifest), encoding="utf-8"
    )


def write_binding(
    root: Path,
    *,
    baseline_sha256: str,
    configuration_digest: str,
    release_version: str,
    measurement_contract: dict[str, object] | None = None,
) -> tuple[dict[str, object], str]:
    contract = measurement_contract or {
        "queue_automation_enabled": False,
        "provider_fields": {
            "queue": {"availability": "unavailable"},
            "tokens": {"availability": "unavailable"},
            "usage": {"availability": "unavailable"},
        },
    }
    record: dict[str, object] = {
        "schema_version": "3",
        "workspace_identity": str(root.resolve()),
        "immutable_source_sha256": "1" * 64,
        "environment_sha256": "2" * 64,
        "event_manifest_sha256": "3" * 64,
        "release_version": release_version,
        "baseline_sha256": baseline_sha256,
        "baseline_configuration_digest": configuration_digest,
        "measurement_contract": contract,
        "selected_adapter": "manual",
        "selected_extensions": [],
        "codex": {
            "path": "/fixture/codex",
            "device": 1,
            "inode": 2,
            "size": 3,
            "mtime_ns": 4,
            "sha256": "4" * 64,
            "version": "0.150.0",
        },
        "auth_mode": "local-login",
        "strict_config_supported": True,
    }
    path = root / "state" / "launch_binding.json"
    raw = (canonical_json(record) + "\n").encode("utf-8")
    path.write_bytes(raw)
    path.chmod(0o600)
    return record, hashlib.sha256(raw).hexdigest()


def build_eligible_runtime(
    root: Path,
    *,
    baseline_sha256: str = "a" * 64,
    configuration_digest: str = "b" * 64,
    release_version: str = "2026.08.28",
    terminal_second: int = 7,
    with_terminal_job: bool = True,
    measurement_contract: dict[str, object] | None = None,
    provider_resource_summary: dict[str, float] | None = None,
) -> list[dict[str, object]]:
    root.mkdir(parents=True, exist_ok=True)
    (root / "VERSION").write_text(release_version + "\n", encoding="utf-8")
    evidence = root / "evidence"
    evidence.mkdir()
    (evidence / "plan.txt").write_text("plan", encoding="utf-8")
    (evidence / "response.json").write_text("{}", encoding="utf-8")
    (root / "state").mkdir()
    (root / "state").chmod(0o700)
    contract = measurement_contract or {
        "queue_automation_enabled": False,
        "provider_fields": {
            "queue": {"availability": "unavailable"},
            "tokens": {"availability": "unavailable"},
            "usage": {"availability": "unavailable"},
        },
    }
    _record, binding_sha256 = write_binding(
        root,
        baseline_sha256=baseline_sha256,
        configuration_digest=configuration_digest,
        release_version=release_version,
        measurement_contract=contract,
    )
    stop_second = terminal_second + 1
    exact_value = "expected-value"
    artifact_reference = "evidence/plan.txt"
    attempt_scope: dict[str, object] = {}
    freshness_requirements: dict[str, object] = {}
    value_sha256 = hashlib.sha256(exact_value.encode("utf-8")).hexdigest()
    attempt_scope_sha256 = hashlib.sha256(
        canonical_json(attempt_scope).encode("utf-8")
    ).hexdigest()
    normalized_value_sha256 = hashlib.sha256(exact_value.encode("utf-8")).hexdigest()
    candidate_identity_sha256 = hashlib.sha256(
        canonical_json(
            {
                "action_kind": "flag",
                "attempt_scope_sha256": attempt_scope_sha256,
                "normalized_value_sha256": normalized_value_sha256,
                "objective_id": "objective-one",
            }
        ).encode("utf-8")
    ).hexdigest()
    proposal_payload: dict[str, object] = {
        "proposal_id": "proposal-one",
        "solver": "solver-one",
        "objective_id": "objective-one",
        "action_kind": "flag",
        "exact_value": exact_value,
        "value_sha256": value_sha256,
        "attempt_scope_sha256": attempt_scope_sha256,
        "normalized_value_sha256": normalized_value_sha256,
        "candidate_identity_sha256": candidate_identity_sha256,
        "artifact_reference": artifact_reference,
        "attempt_scope": attempt_scope,
        "verifier_evidence": [],
        "adapter_id": "manual",
        "freshness_requirements": freshness_requirements,
        "source": "evidence/plan.txt",
        "rationale": "fixture candidate",
        "confidence": "candidate",
        "agent_attempt_id": "attempt-one",
        "parent_rejection_fingerprint": "",
        "discriminator": "",
        "created_at": "2026-08-28T00:00:03Z",
        "stop_generation": 0,
        "policy_generation": 0,
    }
    review_payload: dict[str, object] = {
        "proposal_id": "proposal-one",
        "verdict": "approved",
        "reviewer": "reviewer-one",
        "reason": "fixture independently verified",
        "verifier_report": "",
        "reviewed_at": "2026-08-28T00:00:04Z",
        "stop_generation": 0,
        "policy_generation": 0,
    }
    plan_payload: dict[str, object] = {
        "schema_version": "1",
        "plan_id": "plan-one",
        "generation": 0,
        "policy_generation": 0,
        "adapter_id": "manual",
        "objective_id": "objective-one",
        "proposal_id": "proposal-one",
        "semantic_action": "flag",
        "envelope": {
            "objective_id": "objective-one",
            "action_kind": "flag",
            "exact_value": exact_value,
            "artifact_reference": artifact_reference,
            "attempt_scope": attempt_scope,
            "adapter_id": "manual",
            "policy_generation": 0,
            "freshness_requirements": freshness_requirements,
            "proposal_id": "proposal-one",
        },
        "stages": [
            {"name": "offline_validate", "mutation": False},
            {"name": "adapter_readonly_preflight", "mutation": False},
            {"name": "freshness_and_scope_check", "mutation": False},
            {"name": "consume_authority", "mutation": True},
            {"name": "adapter_execute", "mutation": True},
            {"name": "record_verdict", "mutation": False},
        ],
        "predicates": {
            "proposal_event_id": "proposal",
            "review_event_id": "review",
            "authorization_id": "authorization-one",
            "scope_generation": 0,
            "attempt_scope": attempt_scope,
        },
        "evidence_paths": ["evidence/plan.txt"],
        "success_conditions": [
            "structured scorer verdict accepted or already-accepted",
            "all request/response artifacts preserved",
        ],
        "recovery": {
            "on_reject": "record rejection and near-miss context",
            "on_auth": "block-by-auth without consuming another action",
            "on_stale": "compile a fresh plan",
        },
        "lifecycle_refs": attempt_scope,
        "created_at": "2026-08-28T00:00:05Z",
    }
    plan_payload["plan_sha256"] = hashlib.sha256(
        canonical_json(plan_payload).encode("utf-8")
    ).hexdigest()
    rows = [
        event(
            1,
            f"measurement.started:{binding_sha256}",
            "measurement.started",
            {
                "launch_binding_sha256": binding_sha256,
                "baseline_sha256": baseline_sha256,
                "configuration_digest": configuration_digest,
                "release_version": release_version,
                "stop_generation": 0,
                "policy_generation": 0,
                "scope_generation": 0,
                "measurement_contract": contract,
            },
            actor="system",
            second=1,
        ),
        event(
            2,
            "agent-running",
            "agent.running",
            {
                "agent_id": "agent-one",
                "agent_attempt_id": "attempt-one",
                "objective_id": "objective-one",
                "role": "solver",
            },
            second=2,
        ),
        event(
            3,
            "proposal",
            "proposal.created",
            proposal_payload,
            second=3,
        ),
        event(
            4,
            "review",
            "review.recorded",
            review_payload,
            second=4,
        ),
        event(
            5,
            "plan",
            "execution.planned",
            {**plan_payload, "plan_path": "state/execution_plans/plan-one.json"},
            second=5,
        ),
        event(
            6,
            "authorization-granted",
            "authorization.granted",
            {
                "authorization_id": "authorization-one",
                "mode": "exact",
                "proposal_id": "proposal-one",
                "action_kind": "flag",
                "remaining": 1,
                "reason": "fixture authorization",
                "granted_at": "2026-08-28T00:00:05Z",
                "stop_generation": 0,
                "policy_generation": 0,
            },
            actor="operator",
            second=6,
        ),
        event(
            7,
            "authorization-consumed",
            "authorization.consumed",
            {
                "authorization_id": "authorization-one",
                "consumed_for_plan": "plan-one",
                "proposal_id": "proposal-one",
                "action_kind": "flag",
                "mode": "exact",
                "remaining": 0,
                "reason": "fixture authorization",
                "granted_at": "2026-08-28T00:00:05Z",
                "consumed_at": "2026-08-28T00:00:06Z",
                "stop_generation": 0,
                "policy_generation": 0,
            },
            second=7,
        ),
        event(
            8,
            "execution-started",
            "execution.started",
            {
                "plan_id": "plan-one",
                "proposal_id": "proposal-one",
                "objective_id": "objective-one",
                "action_kind": "flag",
                "stop_generation": 0,
                "policy_generation": 0,
                "scope_generation": 0,
                "review_event_id": "review",
                "authorization_id": "authorization-one",
                "started_at": "2026-08-28T00:00:07Z",
            },
            second=8,
        ),
        event(9, "command-requested", "command.requested", {"command_id": "command-one"}, second=9),
        event(10, "command-completed", "command.completed", {"command_id": "command-one"}, second=10),
        event(
            11,
            "terminal",
            "execution.completed",
            {
                "plan_id": "plan-one",
                "proposal_id": "proposal-one",
                "objective_id": "objective-one",
                "action_kind": "flag",
                "status": "completed",
                "response_path": "evidence/response.json",
                "evidence_root": "evidence",
                "verdict": {"verdict": "accepted", "scorer_truth": "accepted"},
                "completed_at": "2026-08-28T00:00:07Z",
            },
            second=terminal_second,
        ),
        event(
            12,
            "agent-closed",
            "agent.closed",
            {
                "agent_id": "agent-one",
                "agent_attempt_id": "attempt-one",
                "objective_id": "objective-one",
            },
            second=stop_second + 1,
        ),
        event(
            13,
            "outcome",
            "outcome.recorded",
            {
                "outcome_id": "outcome-one",
                "outcome_type": "supported_finding",
                "agent_id": "agent-one",
                "agent_attempt_id": "attempt-one",
                "objective_id": "objective-one",
            },
            second=stop_second + 2,
        ),
        event(
            14,
            "stop",
            "control.stop",
            {
                "reason": "fixture closeout",
                "generation": 1,
                "watcher_epoch": 1,
                "requested_at": f"2026-08-28T00:00:{stop_second + 3:02d}Z",
            },
            actor="operator",
            second=stop_second + 3,
        ),
    ]
    rows[-1]["generation"] = 1
    if with_terminal_job:
        rows.append(
            event(
                15,
                "job-closed",
                "job.closed",
                {
                    "job_id": "job-one",
                    "owner_token": "owner-one",
                    "closed_at": f"2026-08-28T00:00:{stop_second + 4:02d}Z",
                    "resource_summary": {
                        "cpu_seconds": 0.5,
                        "rss_bytes": 1024,
                        "peak_rss_bytes": 2048,
                        **(provider_resource_summary or {}),
                    },
                },
                second=stop_second + 4,
            )
        )
        rows[-1]["generation"] = 1
    else:
        for row in rows:
            if row["event_id"] == "agent-closed":
                row["seq"] = 15
                row["created_at"] = f"2026-08-28T00:00:{stop_second + 4:02d}Z"
                row["generation"] = 1
                break
        rows.sort(key=lambda row: int(row["seq"]))
    write_events(root, rows)
    write_command(root)
    write_evidence_manifest(root)
    return rows


def configure_no_submit_chain(
    root: Path,
    rows: list[dict[str, object]],
    *,
    artifact_reference: str = "evidence/plan.txt",
    exact_value: str = "",
    evidence_root: str | None = None,
) -> list[dict[str, object]]:
    """Convert the fixture chain to one explicit non-scoring evidence terminal."""

    proposal = next(row for row in rows if row["event_id"] == "proposal")
    plan = next(row for row in rows if row["event_id"] == "plan")
    started = next(row for row in rows if row["event_id"] == "execution-started")
    terminal = next(row for row in rows if row["event_id"] == "terminal")
    proposal_payload = proposal["payload"]
    plan_payload = plan["payload"]
    started_payload = started["payload"]
    terminal_payload = terminal["payload"]
    assert isinstance(proposal_payload, dict)
    assert isinstance(plan_payload, dict)
    assert isinstance(started_payload, dict)
    assert isinstance(terminal_payload, dict)

    proposal_payload["action_kind"] = "no_submit_evidence"
    proposal_payload["exact_value"] = exact_value
    proposal_payload["artifact_reference"] = artifact_reference
    proposal_payload["value_sha256"] = (
        hashlib.sha256(exact_value.encode("utf-8")).hexdigest() if exact_value else ""
    )
    proposal_payload["normalized_value_sha256"] = hashlib.sha256(
        (exact_value or artifact_reference).encode("utf-8")
    ).hexdigest()
    proposal_payload["candidate_identity_sha256"] = hashlib.sha256(
        canonical_json(
            {
                "action_kind": "no_submit_evidence",
                "attempt_scope_sha256": proposal_payload["attempt_scope_sha256"],
                "normalized_value_sha256": proposal_payload["normalized_value_sha256"],
                "objective_id": "objective-one",
            }
        ).encode("utf-8")
    ).hexdigest()

    envelope = plan_payload["envelope"]
    predicates = plan_payload["predicates"]
    assert isinstance(envelope, dict)
    assert isinstance(predicates, dict)
    plan_payload["semantic_action"] = "no_submit_evidence"
    envelope["action_kind"] = "no_submit_evidence"
    envelope["exact_value"] = exact_value
    envelope["artifact_reference"] = artifact_reference
    predicates["authorization_id"] = ""
    plan_payload["plan_sha256"] = hashlib.sha256(
        canonical_json(
            {
                key: value
                for key, value in plan_payload.items()
                if key not in {"plan_path", "plan_sha256"}
            }
        ).encode("utf-8")
    ).hexdigest()

    started_payload["action_kind"] = "no_submit_evidence"
    started_payload["authorization_id"] = ""
    terminal_payload["action_kind"] = "no_submit_evidence"
    terminal_payload["verdict"] = {
        "verdict": "non_scoring",
        "scorer_truth": "non_scoring",
        "transport_truth": "not-applicable",
    }
    terminal_payload["response_path"] = ""
    terminal_payload["evidence_root"] = (
        artifact_reference if evidence_root is None else evidence_root
    )
    manifest_evidence_root = terminal_payload["evidence_root"]
    if artifact_reference == "" and not manifest_evidence_root:
        plan_path = plan_payload.get("plan_path")
        assert isinstance(plan_path, str) and plan_path
        retained_plan = root / plan_path
        retained_plan.parent.mkdir(parents=True, exist_ok=True)
        retained_plan.write_text(
            canonical_json(
                {
                    key: value
                    for key, value in plan_payload.items()
                    if key != "plan_path"
                }
            ),
            encoding="utf-8",
        )
        manifest_evidence_root = plan_path
    rows[:] = [
        row
        for row in rows
        if row["event_type"] not in {"authorization.granted", "authorization.consumed"}
    ]
    for sequence, row in enumerate(rows, start=1):
        row["seq"] = sequence
    write_events(root, rows)
    write_evidence_manifest(
        root,
        no_submit_plans={"plan-one"},
        no_submit_evidence_roots={"plan-one": manifest_evidence_root},
    )
    return rows


class TelemetryComparisonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_eligible_runtime_binds_measurement_without_reading_external_baseline(self) -> None:
        root = self.base / "eligible"
        build_eligible_runtime(root)
        external_baseline = self.base / "private-baseline.json"
        external_baseline.write_text("external-secret-value", encoding="utf-8")
        before = external_baseline.read_bytes()

        report = build_report(root)

        readiness = report["comparison_readiness"]
        binding = readiness["gates"]["baseline_binding"]
        self.assertTrue(report["coherent"], report)
        self.assertTrue(readiness["comparison_eligible"], readiness)
        self.assertEqual(
            readiness["effectiveness_claims"],
            {
                "availability": "not_available",
                "reason": "causal_effectiveness_not_established",
            },
        )
        self.assertTrue(binding["passed"])
        self.assertEqual(binding["binding"]["baseline_sha256"], "a" * 64)
        self.assertEqual(binding["binding"]["generations"], {"policy": 0, "scope": 0, "stop": 0})
        self.assertEqual(external_baseline.read_bytes(), before)
        self.assertNotIn("external-secret-value", json.dumps(report, sort_keys=True))

    def test_rehearsal_five_objective_ablations_are_ineligible_until_all_gates_are_honest(self) -> None:
        unavailable = {
            "queue_automation_enabled": False,
            "provider_fields": {
                "queue": {"availability": "unavailable"},
                "tokens": {"availability": "unavailable"},
                "usage": {"availability": "unavailable"},
            },
        }
        enabled_queue = {
            **unavailable,
            "queue_automation_enabled": True,
        }
        enabled_tokens = {
            **unavailable,
            "provider_fields": {
                **unavailable["provider_fields"],
                "tokens": {"availability": "available"},
            },
        }
        cases = {
            "manifest": ("evidence_manifest_missing", unavailable),
            "queue": ("queue_timing_incomplete", enabled_queue),
            "provider": ("provider_tokens_measurement_incomplete", enabled_tokens),
            "empty_manifest": ("evidence_required_references_absent", unavailable),
            "stale": ("stop_reconciliation_incomplete", unavailable),
        }
        for name, (reason, contract) in cases.items():
            with self.subTest(name=name):
                root = self.base / name
                rows = build_eligible_runtime(root, measurement_contract=contract)
                if name == "manifest":
                    (root / "evidence" / "latest-manifest.json").unlink()
                elif name == "empty_manifest":
                    manifest_path = root / "evidence" / "latest-manifest.json"
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    manifest.update(
                        {
                            "required_reference_count": 0,
                            "required_reference_counts": {
                                "empty": 0,
                                "missing": 0,
                                "present_directory": 0,
                                "present_file": 0,
                                "rejected": 0,
                            },
                            "references": [],
                        }
                    )
                    manifest_path.write_text(canonical_json(manifest), encoding="utf-8")
                elif name == "stale":
                    stale = next(row for row in rows if row["event_id"] == "job-closed")
                    stale["event_type"] = "job.stale"
                    write_events(root, rows)
                    write_evidence_manifest(root)

                report = build_report(root)

                self.assertTrue(report["coherent"], report)
                self.assertFalse(report["comparison_readiness"]["comparison_eligible"])
                gates = report["comparison_readiness"]["gates"]
                if name in {"manifest", "empty_manifest"}:
                    self.assertEqual(gates["evidence_completeness"]["reason"], reason)
                else:
                    operational = gates["queue_stop_resource_applicability"]
                    self.assertEqual(operational["reason"], reason)

        comprehensive = self.base / "comprehensive"
        rows = build_eligible_runtime(
            comprehensive,
            measurement_contract={
                "queue_automation_enabled": True,
                "provider_fields": {
                    "queue": {"availability": "available"},
                    "tokens": {"availability": "available"},
                    "usage": {"availability": "available"},
                },
            },
        )
        stale = next(row for row in rows if row["event_id"] == "job-closed")
        stale["event_type"] = "job.stale"
        write_events(comprehensive, rows)
        write_evidence_manifest(comprehensive)
        report = build_report(comprehensive)
        components = report["comparison_readiness"]["gates"][
            "queue_stop_resource_applicability"
        ]["components"]
        self.assertFalse(report["comparison_readiness"]["comparison_eligible"])
        self.assertEqual(components["queue"]["reason"], "queue_timing_incomplete")
        self.assertEqual(
            components["provider_fields"]["tokens"]["reason"],
            "provider_tokens_measurement_incomplete",
        )
        self.assertEqual(components["stop"]["reason"], "stop_reconciliation_incomplete")

        left = self.base / "controlled-left"
        right = self.base / "controlled-right"
        build_eligible_runtime(left, measurement_contract=unavailable)
        build_eligible_runtime(right, measurement_contract=unavailable, terminal_second=8)
        comparison, _left, _right = compare_runtime_roots(left, right)
        self.assertEqual(comparison["comparison_kind"], "descriptive")
        self.assertFalse(comparison["differences"]["provider_availability"]["different"])

    def test_evidence_manifest_cannot_substitute_a_same_count_reference(self) -> None:
        root = self.base / "wrong-reference"
        build_eligible_runtime(root)
        manifest_path = root / "evidence" / "latest-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        plan_reference = next(
            reference
            for reference in manifest["references"]
            if reference["kind"] == "plan_evidence"
        )
        plan_reference["path"] = "evidence/response.json"
        manifest_path.write_text(canonical_json(manifest), encoding="utf-8")

        report = build_report(root)

        gate = report["comparison_readiness"]["gates"]["evidence_completeness"]
        self.assertFalse(gate["passed"])
        self.assertEqual(gate["reason"], "evidence_manifest_terminal_coverage_incomplete")

    def test_required_manifest_files_and_directories_are_descriptor_hash_bound(self) -> None:
        clean = self.base / "manifest-clean"
        build_eligible_runtime(clean)
        self.assertTrue(build_report(clean)["comparison_readiness"]["comparison_eligible"])
        output = self.base / "manifest-refused.json"
        for name, mutate, reason in (
            (
                "file",
                lambda root: (root / "evidence" / "response.json").write_text(
                    '{"tampered":true}', encoding="utf-8"
                ),
                "evidence_manifest_file_hash_mismatch",
            ),
            (
                "directory",
                lambda root: (root / "evidence" / "untracked.txt").write_text(
                    "unexpected\n", encoding="utf-8"
                ),
                "evidence_manifest_directory_hash_mismatch",
            ),
        ):
            with self.subTest(name=name):
                root = self.base / f"manifest-{name}"
                build_eligible_runtime(root)
                mutate(root)

                first = build_report(root)
                second = build_report(root)

                self.assertTrue(first["coherent"], first)
                self.assertEqual(first, second)
                gate = first["comparison_readiness"]["gates"]["evidence_completeness"]
                self.assertFalse(gate["passed"])
                self.assertEqual(gate["reason"], reason)
                self.assertNotIn("tampered", json.dumps(first, sort_keys=True))
                self.assertEqual(compare_main([str(clean), str(root), "--output", str(output)]), 2)
                self.assertFalse(output.exists())

    def test_every_declared_manifest_file_row_is_hash_bound(self) -> None:
        clean = self.base / "manifest-table-clean"
        build_eligible_runtime(clean)
        output = self.base / "manifest-table-refused.json"

        def append_declared_file(root: Path, relative: str, data: bytes) -> None:
            manifest_path = root / "evidence" / "latest-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"].append(
                {
                    "path": relative,
                    "bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
            manifest["file_count"] += 1
            manifest["total_bytes"] += len(data)
            manifest_path.write_text(canonical_json(manifest), encoding="utf-8")

        cases = (
            (
                "same-size-tamper",
                lambda root: (
                    (root / "analysis").mkdir(),
                    (root / "analysis" / "unreferenced.txt").write_bytes(b"A\n"),
                    append_declared_file(root, "analysis/unreferenced.txt", b"A\n"),
                    (root / "analysis" / "unreferenced.txt").write_bytes(b"B\n"),
                ),
                "evidence_manifest_file_hash_mismatch",
            ),
            (
                "missing-file",
                lambda root: (
                    (root / "analysis").mkdir(),
                    append_declared_file(root, "analysis/missing.txt", b"missing\n"),
                ),
                "evidence_manifest_reference_unreadable",
            ),
            (
                "declared-directory",
                lambda root: (
                    (root / "analysis" / "not-a-file").mkdir(parents=True),
                    append_declared_file(root, "analysis/not-a-file", b""),
                ),
                "evidence_manifest_reference_invalid",
            ),
        )
        for name, mutate, reason in cases:
            with self.subTest(name=name):
                root = self.base / f"manifest-table-{name}"
                build_eligible_runtime(root)
                mutate(root)

                first = build_report(root)
                second = build_report(root)

                self.assertTrue(first["coherent"], first)
                self.assertEqual(first, second)
                gate = first["comparison_readiness"]["gates"]["evidence_completeness"]
                self.assertFalse(gate["passed"])
                self.assertEqual(gate["reason"], reason)
                self.assertNotIn("unreferenced", json.dumps(first, sort_keys=True))
                self.assertEqual(compare_main([str(clean), str(root), "--output", str(output)]), 2)
                self.assertFalse(output.exists())

    def test_manifest_descriptor_change_is_detected_during_hash(self) -> None:
        root = self.base / "manifest-descriptor-change"
        root.mkdir()
        evidence = root / "evidence"
        evidence.mkdir()
        (evidence / "response.json").write_text("{}\n", encoding="utf-8")
        original_fstat = os.fstat
        calls = 0

        def changed_fstat(descriptor: int) -> os.stat_result:
            nonlocal calls
            calls += 1
            result = original_fstat(descriptor)
            if calls == 3:
                fields = list(result)
                fields[8] += 1
                return os.stat_result(fields)
            return result

        with mock.patch.object(telemetry_module.os, "fstat", side_effect=changed_fstat):
            value, error = telemetry_module._read_manifest_file(
                root, ("evidence", "response.json")
            )

        self.assertIsNone(value)
        self.assertEqual(error, "evidence_manifest_reference_changed")

    def test_lineage_and_stop_proof_ablations_remain_coherent_and_refuse_comparison(self) -> None:
        clean = self.base / "lineage-clean"
        build_eligible_runtime(clean)
        output = self.base / "lineage-refused.json"

        def rejected_review(rows: list[dict[str, object]]) -> None:
            review = next(row for row in rows if row["event_id"] == "review")
            payload = review["payload"]
            assert isinstance(payload, dict)
            payload["verdict"] = "rejected"

        def no_registration(rows: list[dict[str, object]]) -> None:
            rows[:] = [row for row in rows if row["event_type"] != "agent.running"]

        def no_proposal_link(rows: list[dict[str, object]]) -> None:
            proposal = next(row for row in rows if row["event_id"] == "proposal")
            payload = proposal["payload"]
            assert isinstance(payload, dict)
            del payload["agent_attempt_id"]

        def review_after_plan(rows: list[dict[str, object]]) -> None:
            review = next(row for row in rows if row["event_id"] == "review")
            review["seq"] = 5
            plan = next(row for row in rows if row["event_id"] == "plan")
            plan["seq"] = 4
            rows.sort(key=lambda row: int(row["seq"]))

        def terminal_generation_mismatch(rows: list[dict[str, object]]) -> None:
            terminal = next(row for row in rows if row["event_id"] == "terminal")
            terminal["generation"] = 1

        def consumption_before_plan(rows: list[dict[str, object]]) -> None:
            plan = next(row for row in rows if row["event_id"] == "plan")
            consumption = next(
                row for row in rows if row["event_id"] == "authorization-consumed"
            )
            grant = next(row for row in rows if row["event_id"] == "authorization-granted")
            grant["seq"] = 5
            consumption["seq"] = 6
            plan["seq"] = 7
            rows.sort(key=lambda row: int(row["seq"]))

        def absent_parent(rows: list[dict[str, object]]) -> None:
            running = next(row for row in rows if row["event_type"] == "agent.running")
            payload = running["payload"]
            assert isinstance(payload, dict)
            payload["parent_agent_attempt_id"] = "unregistered-parent"

        def invalid_parent(value: object) -> object:
            def mutate(rows: list[dict[str, object]]) -> None:
                running = next(row for row in rows if row["event_type"] == "agent.running")
                payload = running["payload"]
                assert isinstance(payload, dict)
                payload["parent_agent_attempt_id"] = value

            return mutate

        def invalid_stop(rows: list[dict[str, object]]) -> None:
            stop = next(row for row in rows if row["event_type"] == "control.stop")
            stop["actor"] = "solver"
            stop["payload"] = {}

        cases = (
            ("rejected-review", rejected_review, "final_scoring_chain_lineage"),
            ("no-registration", no_registration, "typed_attempt_coverage"),
            ("no-proposal-link", no_proposal_link, "typed_attempt_coverage"),
            ("review-after-plan", review_after_plan, "final_scoring_chain_lineage"),
            ("consumption-before-plan", consumption_before_plan, "final_scoring_chain_lineage"),
            ("terminal-generation", terminal_generation_mismatch, "final_scoring_chain_lineage"),
            ("absent-parent", absent_parent, "typed_attempt_coverage"),
            ("none-parent", invalid_parent(None), "typed_attempt_coverage"),
            ("list-parent", invalid_parent([]), "typed_attempt_coverage"),
            ("zero-parent", invalid_parent(0), "typed_attempt_coverage"),
            ("invalid-stop", invalid_stop, "queue_stop_resource_applicability"),
        )
        for name, mutate, gate_name in cases:
            with self.subTest(name=name):
                root = self.base / name
                rows = build_eligible_runtime(root)
                mutate(rows)
                write_events(root, rows)
                write_evidence_manifest(root)

                first = build_report(root)
                second = build_report(root)

                self.assertTrue(first["coherent"], first)
                self.assertEqual(first, second)
                self.assertFalse(first["comparison_readiness"]["gates"][gate_name]["passed"])
                self.assertEqual(compare_main([str(clean), str(root), "--output", str(output)]), 2)
                self.assertFalse(output.exists())

    def test_complete_scoring_tuple_ablations_are_private_and_ineligible(self) -> None:
        clean = self.base / "tuple-clean"
        build_eligible_runtime(clean)
        output = self.base / "tuple-refused.json"

        def plan_payload(rows: list[dict[str, object]]) -> dict[str, object]:
            row = next(row for row in rows if row["event_id"] == "plan")
            payload = row["payload"]
            assert isinstance(payload, dict)
            return payload

        def proposal_payload(rows: list[dict[str, object]]) -> dict[str, object]:
            row = next(row for row in rows if row["event_id"] == "proposal")
            payload = row["payload"]
            assert isinstance(payload, dict)
            return payload

        def reseal_plan(payload: dict[str, object]) -> None:
            payload["plan_sha256"] = hashlib.sha256(
                canonical_json(
                    {
                        key: value
                        for key, value in payload.items()
                        if key not in {"plan_path", "plan_sha256"}
                    }
                ).encode("utf-8")
            ).hexdigest()

        def envelope_exact_value(rows: list[dict[str, object]]) -> None:
            payload = plan_payload(rows)
            envelope = payload["envelope"]
            assert isinstance(envelope, dict)
            envelope["exact_value"] = "different-value"
            reseal_plan(payload)

        def envelope_artifact(rows: list[dict[str, object]]) -> None:
            payload = plan_payload(rows)
            envelope = payload["envelope"]
            assert isinstance(envelope, dict)
            envelope["artifact_reference"] = "evidence/different.txt"
            reseal_plan(payload)

        def envelope_freshness(rows: list[dict[str, object]]) -> None:
            payload = plan_payload(rows)
            envelope = payload["envelope"]
            assert isinstance(envelope, dict)
            envelope["freshness_requirements"] = {"recheck": True}
            reseal_plan(payload)

        def candidate_digest(rows: list[dict[str, object]]) -> None:
            proposal_payload(rows)["candidate_identity_sha256"] = "0" * 64

        def malformed_freshness(rows: list[dict[str, object]]) -> None:
            proposal_payload(rows)["freshness_requirements"] = []

        def predicate_review(rows: list[dict[str, object]]) -> None:
            payload = plan_payload(rows)
            predicates = payload["predicates"]
            assert isinstance(predicates, dict)
            predicates["review_event_id"] = "another-review"
            reseal_plan(payload)

        def terminal_tuple(rows: list[dict[str, object]]) -> None:
            terminal = next(row for row in rows if row["event_id"] == "terminal")
            payload = terminal["payload"]
            assert isinstance(payload, dict)
            payload["action_kind"] = "proof_artifact"

        def cross_generation(rows: list[dict[str, object]]) -> None:
            measurement = next(
                row for row in rows if row["event_type"] == "measurement.started"
            )
            payload = measurement["payload"]
            assert isinstance(payload, dict)
            payload["stop_generation"] = 5
            payload["policy_generation"] = 5
            payload["scope_generation"] = 5
            measurement["generation"] = 5

        cases = (
            ("exact-value", envelope_exact_value),
            ("artifact-reference", envelope_artifact),
            ("freshness", envelope_freshness),
            ("candidate-digest", candidate_digest),
            ("malformed-freshness", malformed_freshness),
            ("review-predicate", predicate_review),
            ("terminal-tuple", terminal_tuple),
            ("cross-generation", cross_generation),
        )
        for name, mutate in cases:
            with self.subTest(name=name):
                root = self.base / f"tuple-{name}"
                rows = build_eligible_runtime(root)
                mutate(rows)
                write_events(root, rows)
                write_evidence_manifest(root)

                first = build_report(root)
                second = build_report(root)

                self.assertTrue(first["coherent"], first)
                self.assertEqual(first, second)
                self.assertFalse(
                    first["comparison_readiness"]["gates"][
                        "final_scoring_chain_lineage"
                    ]["passed"]
                )
                if name == "cross-generation":
                    stop_gate = first["comparison_readiness"]["gates"][
                        "queue_stop_resource_applicability"
                    ]["components"]["stop"]
                    self.assertEqual(
                        stop_gate["reason"], "final_control_stop_precedes_measurement"
                    )
                rendered = json.dumps(first, sort_keys=True)
                self.assertNotIn("expected-value", rendered)
                self.assertNotIn("different-value", rendered)
                self.assertEqual(compare_main([str(clean), str(root), "--output", str(output)]), 2)
                self.assertFalse(output.exists())

    def test_retry_grant_and_timeline_gate_regressions_refuse_comparison(self) -> None:
        clean = self.base / "integrity-clean"
        build_eligible_runtime(clean)
        output = self.base / "integrity-refused.json"

        def proposal(rows: list[dict[str, object]]) -> dict[str, object]:
            value = next(row for row in rows if row["event_id"] == "proposal")["payload"]
            assert isinstance(value, dict)
            return value

        def grant(rows: list[dict[str, object]]) -> dict[str, object]:
            value = next(row for row in rows if row["event_id"] == "authorization-granted")["payload"]
            assert isinstance(value, dict)
            return value

        def reindex(rows: list[dict[str, object]]) -> None:
            for sequence, row in enumerate(rows, start=1):
                row["seq"] = sequence

        def invalid_parent(rows: list[dict[str, object]]) -> None:
            proposal(rows)["parent_rejection_fingerprint"] = "not-a-fingerprint"
            proposal(rows)["discriminator"] = "different method"

        def orphan_parent(rows: list[dict[str, object]]) -> None:
            proposal(rows)["parent_rejection_fingerprint"] = "a" * 64
            proposal(rows)["discriminator"] = "different method"

        def discriminator_without_parent(rows: list[dict[str, object]]) -> None:
            proposal(rows)["discriminator"] = "different method"

        def missing_grant(rows: list[dict[str, object]]) -> None:
            rows[:] = [row for row in rows if row["event_type"] != "authorization.granted"]
            reindex(rows)

        def duplicate_grant(rows: list[dict[str, object]]) -> None:
            original = next(row for row in rows if row["event_type"] == "authorization.granted")
            duplicate = {**original, "event_id": "authorization-granted-duplicate"}
            position = rows.index(original)
            rows.insert(position + 1, duplicate)
            reindex(rows)

        def stale_grant(rows: list[dict[str, object]]) -> None:
            grant(rows)["policy_generation"] = 1

        def substituted_grant(rows: list[dict[str, object]]) -> None:
            grant(rows)["proposal_id"] = "different-proposal"

        def overconsumed_grant(rows: list[dict[str, object]]) -> None:
            grant(rows)["remaining"] = 0

        def late_measurement(rows: list[dict[str, object]]) -> None:
            measurement = next(row for row in rows if row["event_type"] == "measurement.started")
            rows.remove(measurement)
            rows.insert(3, measurement)
            reindex(rows)

        def future_attempt(rows: list[dict[str, object]]) -> None:
            running = next(row for row in rows if row["event_type"] == "agent.running")
            running["generation"] = 5

        def future_scoring(rows: list[dict[str, object]]) -> None:
            for row in rows:
                if row["event_type"] in {
                    "proposal.created", "review.recorded", "authorization.granted",
                    "authorization.consumed", "execution.planned", "execution.started",
                    "execution.completed",
                }:
                    row["generation"] = 5

        cases = (
            ("invalid-parent", invalid_parent, "final_scoring_chain_lineage"),
            ("orphan-parent", orphan_parent, "final_scoring_chain_lineage"),
            ("orphan-discriminator", discriminator_without_parent, "final_scoring_chain_lineage"),
            ("missing-grant", missing_grant, "final_scoring_chain_lineage"),
            ("duplicate-grant", duplicate_grant, "final_scoring_chain_lineage"),
            ("stale-grant", stale_grant, "final_scoring_chain_lineage"),
            ("substituted-grant", substituted_grant, "final_scoring_chain_lineage"),
            ("overconsumed-grant", overconsumed_grant, "final_scoring_chain_lineage"),
            ("late-measurement", late_measurement, "measurement_timeline_generation"),
            ("future-attempt", future_attempt, "measurement_timeline_generation"),
            ("future-scoring", future_scoring, "measurement_timeline_generation"),
        )
        for name, mutate, gate_name in cases:
            with self.subTest(name=name):
                root = self.base / f"integrity-{name}"
                rows = build_eligible_runtime(root)
                mutate(rows)
                write_events(root, rows)
                write_evidence_manifest(root)
                first = build_report(root)
                second = build_report(root)
                self.assertTrue(first["coherent"], first)
                self.assertEqual(first, second)
                self.assertFalse(first["comparison_readiness"]["gates"][gate_name]["passed"])
                self.assertEqual(compare_main([str(clean), str(root), "--output", str(output)]), 2)
                self.assertFalse(output.exists())

    def test_measurement_timeline_accepts_stop_resume_generation_rotation(self) -> None:
        rows = [
            event(
                1,
                "measurement",
                "measurement.started",
                {"stop_generation": 0, "policy_generation": 0, "scope_generation": 0},
                actor="system",
            ),
            event(
                2,
                "stop-one",
                "control.stop",
                {"generation": 1},
                actor="operator",
            ),
            event(3, "resume-one", "control.resume", {"generation": 1}, actor="operator"),
            event(
                4,
                "generation-one-proposal",
                "proposal.created",
                {"proposal_id": "generation-one"},
            ),
            event(
                5,
                "stop-two",
                "control.stop",
                {"generation": 2},
                actor="operator",
            ),
        ]
        for row in rows[1:]:
            row["generation"] = 1 if row["seq"] in {2, 3, 4} else 2

        passed = telemetry_module._measurement_timeline_generation_gate(
            rows, {"stop": 0, "policy": 0, "scope": 0}
        )

        self.assertTrue(passed["passed"], passed)
        rows_without_resume = [row for row in rows if row["event_type"] != "control.resume"]
        failed = telemetry_module._measurement_timeline_generation_gate(
            rows_without_resume, {"stop": 0, "policy": 0, "scope": 0}
        )
        self.assertFalse(failed["passed"])
        self.assertEqual(failed["reason"], "measurement_generation_context_incomplete")

    def test_runtime_root_accepts_allowance_and_stop_resume_generation(self) -> None:
        root = self.base / "allowance-resume"
        rows = build_eligible_runtime(root)
        final_stop = next(row for row in rows if row["event_id"] == "stop")
        final_stop["event_id"] = "stop-two"
        final_stop["generation"] = 2
        final_stop_payload = final_stop["payload"]
        assert isinstance(final_stop_payload, dict)
        final_stop_payload.update({"generation": 2, "watcher_epoch": 2})
        job = next(row for row in rows if row["event_id"] == "job-closed")
        job["generation"] = 2
        grant = next(row for row in rows if row["event_id"] == "authorization-granted")
        consumed = next(row for row in rows if row["event_id"] == "authorization-consumed")
        for row in (grant, consumed):
            payload = row["payload"]
            assert isinstance(payload, dict)
            payload["mode"] = "allowance"
            payload.pop("proposal_id", None)
            payload["remaining"] = 2 if row is grant else 1

        stop_one = event(
            2, "stop-one", "control.stop",
            {"reason": "rotation", "generation": 1, "watcher_epoch": 1, "requested_at": "2026-08-28T00:00:02Z"},
            actor="operator", second=2,
        )
        stop_one["generation"] = 1
        resume_one = event(3, "resume-one", "control.resume", {"generation": 1}, actor="operator", second=3)
        resume_one["generation"] = 1
        rows = [rows[0], stop_one, resume_one, *rows[1:]]
        for row in rows[3:]:
            if row["event_type"] != "control.stop" and row["event_id"] != "job-closed":
                row["generation"] = 1
        proposal = next(row for row in rows if row["event_id"] == "proposal")
        review = next(row for row in rows if row["event_id"] == "review")
        plan = next(row for row in rows if row["event_id"] == "plan")
        started = next(row for row in rows if row["event_id"] == "execution-started")
        for row in (proposal, review, grant, consumed, started):
            payload = row["payload"]
            assert isinstance(payload, dict)
            for key in ("stop_generation", "policy_generation", "scope_generation"):
                if key in payload:
                    payload[key] = 1
        plan_payload = plan["payload"]
        assert isinstance(plan_payload, dict)
        plan_payload["generation"] = 1
        plan_payload["policy_generation"] = 1
        envelope = plan_payload["envelope"]
        predicates = plan_payload["predicates"]
        assert isinstance(envelope, dict) and isinstance(predicates, dict)
        envelope["policy_generation"] = 1
        predicates["scope_generation"] = 1
        plan_payload["plan_sha256"] = hashlib.sha256(canonical_json({key: value for key, value in plan_payload.items() if key not in {"plan_path", "plan_sha256"}}).encode("utf-8")).hexdigest()
        for sequence, row in enumerate(rows, start=1):
            row["seq"] = sequence
        write_events(root, rows)
        write_evidence_manifest(root)

        report = build_report(root)
        output = self.base / "allowance-resume-comparison.json"

        self.assertTrue(report["comparison_readiness"]["comparison_eligible"], report)
        self.assertEqual(compare_main([str(root), str(root), "--output", str(output)]), 0)
        self.assertTrue(output.is_file())

    def test_proposal_action_and_candidate_material_semantics_fail_closed(self) -> None:
        clean = self.base / "candidate-semantics-clean"
        build_eligible_runtime(clean)
        output = self.base / "candidate-semantics-refused.json"

        def proposal(rows: list[dict[str, object]]) -> dict[str, object]:
            row = next(row for row in rows if row["event_id"] == "proposal")
            payload = row["payload"]
            assert isinstance(payload, dict)
            return payload

        def reseal_candidate(payload: dict[str, object]) -> None:
            exact = payload["exact_value"]
            artifact = payload["artifact_reference"]
            scope = payload["attempt_scope"]
            assert isinstance(exact, str)
            assert isinstance(artifact, str)
            assert isinstance(scope, dict)
            scope_sha = hashlib.sha256(canonical_json(scope).encode("utf-8")).hexdigest()
            normalized_sha = hashlib.sha256(
                (exact or artifact).encode("utf-8")
            ).hexdigest()
            payload["value_sha256"] = (
                hashlib.sha256(exact.encode("utf-8")).hexdigest() if exact else ""
            )
            payload["attempt_scope_sha256"] = scope_sha
            payload["normalized_value_sha256"] = normalized_sha
            payload["candidate_identity_sha256"] = hashlib.sha256(
                canonical_json(
                    {
                        "action_kind": payload["action_kind"],
                        "attempt_scope_sha256": scope_sha,
                        "normalized_value_sha256": normalized_sha,
                        "objective_id": payload["objective_id"],
                    }
                ).encode("utf-8")
            ).hexdigest()

        def arbitrary_action(rows: list[dict[str, object]]) -> None:
            item = proposal(rows)
            item["action_kind"] = "arbitrary-action"
            reseal_candidate(item)

        def empty_flag(rows: list[dict[str, object]]) -> None:
            item = proposal(rows)
            item["exact_value"] = ""
            reseal_candidate(item)

        def empty_proof(rows: list[dict[str, object]]) -> None:
            item = proposal(rows)
            item["action_kind"] = "proof_artifact"
            item["exact_value"] = ""
            item["artifact_reference"] = ""
            reseal_candidate(item)

        def empty_no_submit(rows: list[dict[str, object]]) -> None:
            item = proposal(rows)
            item["action_kind"] = "no_submit_evidence"
            item["exact_value"] = ""
            item["artifact_reference"] = ""
            reseal_candidate(item)

        def empty_solver(rows: list[dict[str, object]]) -> None:
            proposal(rows)["solver"] = ""

        for name, mutate in (
            ("arbitrary-action", arbitrary_action),
            ("empty-flag", empty_flag),
            ("empty-proof", empty_proof),
            ("empty-no-submit", empty_no_submit),
            ("empty-solver", empty_solver),
        ):
            with self.subTest(name=name):
                root = self.base / f"candidate-semantics-{name}"
                rows = build_eligible_runtime(root)
                mutate(rows)
                write_events(root, rows)
                write_evidence_manifest(root)

                first = build_report(root)
                second = build_report(root)

                self.assertTrue(first["coherent"], first)
                self.assertEqual(first, second)
                gate = first["comparison_readiness"]["gates"][
                    "final_scoring_chain_lineage"
                ]
                self.assertFalse(gate["passed"])
                self.assertEqual(gate["reason"], "scoring_chain_candidate_integrity_mismatch")
                self.assertEqual(compare_main([str(clean), str(root), "--output", str(output)]), 2)
                self.assertFalse(output.exists())

    def test_provider_only_and_zero_terminal_provider_cohorts_are_ineligible(self) -> None:
        clean = self.base / "provider-clean"
        build_eligible_runtime(clean)
        output = self.base / "provider-refused.json"
        provider_available = {
            "queue_automation_enabled": False,
            "provider_fields": {
                "queue": {"availability": "unavailable"},
                "tokens": {"availability": "available"},
                "usage": {"availability": "unavailable"},
            },
        }
        cases = (
            ("provider-only", True, None, "owned_local_process_resource_coverage_incomplete"),
            ("zero-terminal", False, provider_available, "provider_tokens_terminal_jobs_absent"),
        )
        for name, provider_only, contract, reason in cases:
            with self.subTest(name=name):
                root = self.base / name
                rows = build_eligible_runtime(
                    root,
                    measurement_contract=contract,
                    with_terminal_job=not (name == "zero-terminal"),
                )
                if provider_only:
                    job = next(row for row in rows if row["event_id"] == "job-closed")
                    payload = job["payload"]
                    assert isinstance(payload, dict)
                    payload["resource_summary"] = {"provider_token_count": 9}
                    write_events(root, rows)
                    write_evidence_manifest(root)

                report = build_report(root)

                self.assertTrue(report["coherent"], report)
                operational = report["comparison_readiness"]["gates"][
                    "queue_stop_resource_applicability"
                ]
                self.assertFalse(operational["passed"])
                self.assertEqual(operational["reason"], reason)
                self.assertEqual(compare_main([str(clean), str(root), "--output", str(output)]), 2)
                self.assertFalse(output.exists())

    def test_capacity_rejection_shape_is_exact_and_unowned_jobs_do_not_break_local_coverage(self) -> None:
        root = self.base / "valid-capacity-and-unowned"
        rows = build_eligible_runtime(root)
        stop = next(row for row in rows if row["event_type"] == "control.stop")
        job = next(row for row in rows if row["event_id"] == "job-closed")
        stop["seq"] = 15
        job["seq"] = 16
        capacity = event(
            14,
            "capacity-rejected",
            "agent.capacity_rejected",
            {
                "agent_id": "agent-capacity",
                "agent_attempt_id": "attempt-capacity",
                "parent_agent_attempt_id": "",
                "objective_id": "objective-capacity",
                "status": "capacity_rejected",
                "outcome_type": "capacity_failure",
                "active_workers": 1,
                "max_workers": 1,
                "reason": "fixture capacity limit",
                "rejected_at": "2026-08-28T00:00:10Z",
            },
            actor="coordinator",
            second=10,
        )
        unmanaged = event(
            17,
            "unowned-unmanaged",
            "job.unmanaged",
            {"job_id": "unowned-job"},
            second=15,
        )
        unmanaged["generation"] = 1
        rows.extend([capacity, unmanaged])
        rows.sort(key=lambda row: int(row["seq"]))
        write_events(root, rows)
        write_evidence_manifest(root)

        report = build_report(root)

        self.assertTrue(report["coherent"], report)
        self.assertTrue(report["comparison_readiness"]["comparison_eligible"], report)
        attempts = report["comparison_readiness"]["gates"]["typed_attempt_coverage"]
        self.assertEqual(attempts["capacity_rejection_denominator"], 1)

        malformed_root = self.base / "malformed-capacity"
        malformed_rows = build_eligible_runtime(malformed_root)
        malformed_stop = next(
            row for row in malformed_rows if row["event_type"] == "control.stop"
        )
        malformed_job = next(
            row for row in malformed_rows if row["event_id"] == "job-closed")
        malformed_stop["seq"] = 15
        malformed_job["seq"] = 16
        malformed_rows.append(
            event(
                14,
                "capacity-malformed",
                "agent.capacity_rejected",
                {"agent_attempt_id": "malformed-capacity"},
                second=10,
            )
        )
        malformed_rows.sort(key=lambda row: int(row["seq"]))
        write_events(malformed_root, malformed_rows)
        write_evidence_manifest(malformed_root)
        output = self.base / "malformed-capacity-refused.json"

        malformed = build_report(malformed_root)

        self.assertTrue(malformed["coherent"], malformed)
        gate = malformed["comparison_readiness"]["gates"]["typed_attempt_coverage"]
        self.assertFalse(gate["passed"])
        self.assertEqual(gate["reason"], "agent_attempt_identifiers_incomplete")
        self.assertEqual(compare_main([str(root), str(malformed_root), "--output", str(output)]), 2)
        self.assertFalse(output.exists())

    def test_no_submit_evidence_chain_needs_no_authorization(self) -> None:
        root = self.base / "no-submit"
        rows = build_eligible_runtime(root)
        configure_no_submit_chain(root, rows)

        chain = telemetry_module._scoring_chain_gate(rows, {"policy": 0, "scope": 0, "stop": 0})
        report = build_report(root)

        self.assertTrue(chain["passed"], chain)
        self.assertTrue(report["coherent"], report)
        self.assertTrue(report["comparison_readiness"]["comparison_eligible"], report)
        output = self.base / "no-submit-comparison.json"
        self.assertEqual(compare_main([str(root), str(root), "--output", str(output)]), 0)
        self.assertTrue(output.is_file())
        output.unlink()

        artifact = root / "evidence" / "plan.txt"
        original_artifact = artifact.read_bytes()
        artifact.unlink()
        missing_first = build_report(root)
        missing_second = build_report(root)
        self.assertTrue(missing_first["coherent"], missing_first)
        self.assertEqual(missing_first, missing_second)
        self.assertFalse(missing_first["comparison_readiness"]["comparison_eligible"])
        self.assertEqual(compare_main([str(root), str(root), "--output", str(output)]), 2)
        self.assertFalse(output.exists())
        artifact.write_bytes(original_artifact)

        artifact.write_bytes(b"tampered\n")
        tampered_first = build_report(root)
        tampered_second = build_report(root)
        self.assertTrue(tampered_first["coherent"], tampered_first)
        self.assertEqual(tampered_first, tampered_second)
        self.assertFalse(tampered_first["comparison_readiness"]["comparison_eligible"])
        self.assertNotIn("tampered", json.dumps(tampered_first, sort_keys=True))
        self.assertEqual(compare_main([str(root), str(root), "--output", str(output)]), 2)
        self.assertFalse(output.exists())

    def test_missing_duplicate_and_tampered_binding_records_remain_ineligible(self) -> None:
        for case in ("missing", "duplicate", "tampered"):
            with self.subTest(case=case):
                root = self.base / case
                rows = build_eligible_runtime(root)
                binding_path = root / "state" / "launch_binding.json"
                if case == "missing":
                    binding_path.unlink()
                elif case == "duplicate":
                    duplicate = dict(rows[0])
                    duplicate["seq"] = 16
                    duplicate["event_id"] = "measurement.started:duplicate"
                    duplicate["created_at"] = "2026-08-28T00:00:30Z"
                    rows.append(duplicate)
                    write_events(root, rows)
                else:
                    record = json.loads(binding_path.read_text(encoding="utf-8"))
                    record["baseline_sha256"] = "c" * 64
                    binding_path.write_text(canonical_json(record) + "\n", encoding="utf-8")
                    binding_path.chmod(0o600)

                report = build_report(root)

                self.assertTrue(report["coherent"], report)
                gate = report["comparison_readiness"]["gates"]["baseline_binding"]
                self.assertFalse(gate["passed"])
                self.assertEqual(gate["availability"], "not_available")
                self.assertFalse(report["comparison_readiness"]["comparison_eligible"])

    def test_preserved_old_report_is_coherent_but_ineligible(self) -> None:
        root = self.base / "old"
        write_events(root, [event(1, "old", "goal.set")])

        report = build_report(root)

        self.assertTrue(report["coherent"], report)
        self.assertFalse(report["comparison_readiness"]["comparison_eligible"])
        self.assertEqual(
            report["comparison_readiness"]["gates"]["baseline_binding"]["reason"],
            "baseline_binding_missing",
        )

    def test_completed_runtime_requires_a_final_control_stop(self) -> None:
        root = self.base / "no-final-stop"
        rows = build_eligible_runtime(root)
        write_events(root, [row for row in rows if row["event_type"] != "control.stop"])

        report = build_report(root)

        self.assertTrue(report["coherent"], report)
        self.assertFalse(report["comparison_readiness"]["comparison_eligible"])
        operational = report["comparison_readiness"]["gates"][
            "queue_stop_resource_applicability"
        ]
        self.assertFalse(operational["passed"])
        self.assertEqual(operational["components"]["stop"]["reason"], "final_control_stop_absent")

    def test_completed_runtime_refuses_post_stop_mutation(self) -> None:
        cases = {
            "proposal": (
                "proposal.created",
                {"proposal_id": "post-stop", "agent_attempt_id": "attempt-two"},
            ),
            "queue": ("queue.scheduled", {"proposal_id": "proposal-one"}),
            "policy": ("policy.changed", {"generation": 0}),
            "resume": ("control.resume", {"generation": 0}),
            "execution": (
                "execution.completed",
                {"plan_id": "plan-one", "proposal_id": "proposal-one"},
            ),
        }
        for name, (event_type, payload) in cases.items():
            with self.subTest(name=name):
                root = self.base / f"post-stop-{name}"
                rows = build_eligible_runtime(root)
                post_stop = event(16, f"post-stop-{name}", event_type, payload, second=31)
                post_stop["generation"] = 1
                rows.append(post_stop)
                write_events(root, rows)

                report = build_report(root)

                self.assertTrue(report["coherent"], report)
                operational = report["comparison_readiness"]["gates"][
                    "queue_stop_resource_applicability"
                ]
                self.assertFalse(operational["passed"])
                self.assertFalse(report["comparison_readiness"]["comparison_eligible"])

    def test_duplicate_command_lifecycle_event_is_not_exact(self) -> None:
        root = self.base / "duplicate-command"
        rows = build_eligible_runtime(root)
        rows.append(
            event(
                16,
                "command-requested-duplicate",
                "command.requested",
                {"command_id": "command-one"},
                second=31,
            )
        )
        write_events(root, rows)

        report = build_report(root)

        self.assertTrue(report["coherent"], report)
        gate = report["comparison_readiness"]["gates"]["command_lifecycle"]
        self.assertFalse(gate["passed"])
        self.assertEqual(gate["reason"], "command_lifecycle_incomplete")

    def test_not_applicable_resources_are_not_rendered_as_zero_coverage(self) -> None:
        left_root = self.base / "resource-left"
        right_root = self.base / "resource-right"
        build_eligible_runtime(left_root)
        build_eligible_runtime(right_root, with_terminal_job=False)

        comparison, _left, _right = compare_runtime_roots(left_root, right_root)

        names = {metric["name"] for metric in comparison["metrics"]}
        self.assertNotIn("terminal_job_resource_coverage", names)
        resources = comparison["confounders"]["operational_applicability"]
        self.assertTrue(resources["different"])

    def test_comparator_emits_only_descriptive_bounded_deltas_for_mismatched_reports(self) -> None:
        left_root = self.base / "left-runtime"
        right_root = self.base / "right-runtime"
        build_eligible_runtime(left_root)
        build_eligible_runtime(
            right_root,
            baseline_sha256="c" * 64,
            configuration_digest="d" * 64,
            release_version="2026.08.29",
            terminal_second=9,
        )
        self.assertTrue(build_report(left_root)["comparison_readiness"]["comparison_eligible"])
        self.assertTrue(build_report(right_root)["comparison_readiness"]["comparison_eligible"])
        before = {left_root: runtime_snapshot(left_root), right_root: runtime_snapshot(right_root)}
        output = self.base / "comparison.json"

        self.assertEqual(compare_main([str(left_root), str(right_root), "--output", str(output)]), 0)
        comparison = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(comparison["comparison_kind"], "descriptive")
        self.assertTrue(comparison["differences"]["baseline"]["different"])
        self.assertTrue(comparison["differences"]["configuration"]["different"])
        self.assertTrue(comparison["differences"]["release"]["different"])
        latency = next(metric for metric in comparison["metrics"] if metric["kind"] == "latency_seconds")
        self.assertEqual(latency["left"]["numerator"], 1)
        self.assertEqual(latency["left"]["denominator"], 1)
        self.assertEqual(latency["p50_delta"], 2.0)
        self.assertEqual(latency["p95_delta"], 2.0)
        self.assertEqual(before[left_root], runtime_snapshot(left_root))
        self.assertEqual(before[right_root], runtime_snapshot(right_root))
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        rendered = json.dumps(comparison, sort_keys=True).lower()
        self.assertNotIn("effective", rendered)
        self.assertNotIn("causal", rendered)
        self.assertNotIn("improv", rendered)

    def test_comparator_surfaces_provider_availability_as_a_confounder(self) -> None:
        left_root = self.base / "provider-left"
        right_root = self.base / "provider-right"
        build_eligible_runtime(left_root)
        provider_contract = {
            "queue_automation_enabled": False,
            "provider_fields": {
                "queue": {"availability": "unavailable"},
                "tokens": {"availability": "available"},
                "usage": {"availability": "unavailable"},
            },
        }
        build_eligible_runtime(
            right_root,
            measurement_contract=provider_contract,
            provider_resource_summary={"provider_token_count": 7},
        )

        comparison, _left, _right = compare_runtime_roots(left_root, right_root)

        availability = comparison["differences"]["provider_availability"]
        self.assertTrue(availability["different"])
        self.assertEqual(availability["left"]["tokens"], "unavailable")
        self.assertEqual(availability["right"]["tokens"], "available")
        rendered = json.dumps(comparison, sort_keys=True).lower()
        self.assertNotIn("causal", rendered)
        self.assertNotIn("effective", rendered)

    def test_comparator_refuses_forged_report_json_and_ineligible_runtime(self) -> None:
        forged = self.base / "forged-report.json"
        gate_names = (
            "canonical_coherence",
            "command_scan",
            "command_lifecycle",
            "evidence_completeness",
            "baseline_binding",
            "final_scoring_chain_lineage",
            "typed_attempt_coverage",
            "queue_stop_resource_applicability",
        )
        forged_gates = {name: {"passed": True} for name in gate_names}
        forged_gates["baseline_binding"] = {
            "passed": True,
            "binding": {
                "baseline_sha256": "a" * 64,
                "configuration_digest": "b" * 64,
                "launch_binding_sha256": "c" * 64,
                "release_version": "2026.08.28",
                "generations": {"policy": 0, "scope": 0, "stop": 0},
            },
        }
        forged.write_text(
            canonical_json(
                {
                    "schema_version": "2",
                    "report_kind": "rookery.telemetry",
                    "coherent": True,
                    "release_version": "2026.08.28",
                    "canonical": {"jsonl_rows": 1},
                    "measurement": {},
                    "events": {},
                    "comparison_readiness": {
                        "comparison_eligible": True,
                        "gates": forged_gates,
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        output = self.base / "refused.json"

        self.assertEqual(compare_main([str(forged), str(forged), "--output", str(output)]), 2)
        self.assertFalse(output.exists())

        eligible_root = self.base / "eligible-for-refusal"
        build_eligible_runtime(eligible_root)
        old_root = self.base / "old-for-refusal"
        write_events(old_root, [event(1, "old", "goal.set")])
        self.assertEqual(compare_main([str(eligible_root), str(old_root), "--output", str(output)]), 2)
        self.assertFalse(output.exists())

    def test_comparator_refuses_mutated_binding_or_canonical_runtime(self) -> None:
        left_root = self.base / "mutation-left"
        binding_root = self.base / "mutation-binding"
        canonical_root = self.base / "mutation-canonical"
        build_eligible_runtime(left_root)
        build_eligible_runtime(binding_root)
        build_eligible_runtime(canonical_root)
        output = self.base / "mutation-comparison.json"

        binding = binding_root / "state" / "launch_binding.json"
        record = json.loads(binding.read_text(encoding="utf-8"))
        record["baseline_sha256"] = "f" * 64
        binding.write_text(canonical_json(record) + "\n", encoding="utf-8")
        binding.chmod(0o600)
        self.assertEqual(compare_main([str(left_root), str(binding_root), "--output", str(output)]), 2)
        self.assertFalse(output.exists())

        events_path = canonical_root / "state" / "events.jsonl"
        events_path.write_text("{not canonical evidence}\n", encoding="utf-8")
        self.assertEqual(compare_main([str(left_root), str(canonical_root), "--output", str(output)]), 2)
        self.assertFalse(output.exists())

    def test_comparator_output_cannot_be_inside_analyzed_runtime(self) -> None:
        left_root = self.base / "inside-left"
        right_root = self.base / "inside-right"
        build_eligible_runtime(left_root)
        build_eligible_runtime(right_root)
        output = left_root / "comparison.json"

        self.assertEqual(compare_main([str(left_root), str(right_root), "--output", str(output)]), 2)
        self.assertFalse(output.exists())

    def test_comparator_accepts_distinct_source_root_remaps(self) -> None:
        left_root = self.base / "source-left"
        right_root = self.base / "source-right"
        left_rows = build_eligible_runtime(left_root)
        right_rows = build_eligible_runtime(right_root)
        remap_evidence_paths(left_rows, "/deployed/left")
        remap_evidence_paths(right_rows, "/deployed/right")
        write_events(left_root, left_rows)
        write_events(right_root, right_rows)
        output = self.base / "source-comparison.json"

        self.assertEqual(
            compare_main(
                [
                    str(left_root),
                    str(right_root),
                    "--left-source-root",
                    "/deployed/left",
                    "--right-source-root",
                    "/deployed/right",
                    "--output",
                    str(output),
                ]
            ),
            0,
        )
        self.assertTrue(output.is_file())

    def test_comparator_refuses_runtime_that_changes_between_read_only_passes(self) -> None:
        root = self.base / "moving-runtime"
        build_eligible_runtime(root)
        first = build_report(root)
        changed = json.loads(canonical_json(first))
        changed["canonical"]["jsonl_rows"] += 1

        with mock.patch.object(
            telemetry_compare_module,
            "build_report",
            side_effect=[first, changed],
        ), self.assertRaisesRegex(TelemetryComparisonError, "runtime_changed_during_analysis"):
            telemetry_compare_module._stable_runtime_report(root)

    def test_public_stop_prompt_closeout_event_shape_remains_eligible(self) -> None:
        root = self.base / "public-stop-shape"
        rows = build_eligible_runtime(root)
        rows = [row for row in rows if row["event_type"] != "outcome.recorded"]
        rows.extend(
            [
                event(
                    16,
                    "lessons-created-generation-1",
                    "lessons.created",
                    {
                        "path": "docs/retrospectives/lessons-learned-fixture.md",
                        "stop_generation": 1,
                        "purpose": "future-Rookery-improvements-only",
                    },
                    actor="coordinator",
                    second=31,
                ),
                event(
                    17,
                    "post-stop-outcome",
                    "outcome.recorded",
                    {
                        "outcome_id": "outcome-one",
                        "outcome_type": "supported_finding",
                        "agent_id": "agent-one",
                        "agent_attempt_id": "attempt-one",
                        "objective_id": "objective-one",
                    },
                    actor="coordinator",
                    second=32,
                ),
                event(
                    18,
                    "post-stop-harvest",
                    "report.harvested",
                    {"report_path": "analysis/public-stop/REPORT.md"},
                    actor="coordinator",
                    second=33,
                ),
                event(
                    19,
                    "post-stop-capsule",
                    "solve.capsule",
                    {"objective_id": "public-stop-objective"},
                    actor="coordinator",
                    second=34,
                ),
                event(
                    20,
                    "post-stop-complete",
                    "task.completed",
                    {"completion_id": "public-stop-closeout"},
                    actor="coordinator",
                    second=35,
                ),
            ]
        )
        for row in rows:
            if int(row["seq"]) >= 16:
                row["generation"] = 1
        write_events(root, rows)

        report = build_report(root)

        self.assertTrue(report["coherent"], report)
        self.assertTrue(report["comparison_readiness"]["comparison_eligible"], report)

    def test_temporal_and_generation_coverage_refuse_invalid_and_future_work(self) -> None:
        cases: tuple[tuple[str, str], ...] = (
            ("queue", "queue.scheduled"),
            ("platform", "platform.snapshot"),
            ("scope", "scope.compiled"),
            ("policy", "policy.updated"),
        )
        for name, event_type in cases:
            with self.subTest(name=name):
                root = self.base / f"future-{name}"
                rows = build_eligible_runtime(root)
                future = event(2, f"future-{name}", event_type, {}, second=2)
                future["generation"] = 99
                rows.insert(1, future)
                for sequence, row in enumerate(rows, start=1):
                    row["seq"] = sequence
                write_events(root, rows)
                write_evidence_manifest(root)

                report = build_report(root)

                self.assertTrue(report["coherent"], report)
                self.assertFalse(report["comparison_readiness"]["comparison_eligible"])
                self.assertEqual(
                    report["comparison_readiness"]["gates"][
                        "measurement_timeline_generation"
                    ]["reason"],
                    "measurement_generation_context_incomplete",
                )

        root = self.base / "invalid-temporal-coverage"
        rows = build_eligible_runtime(root)
        for row in rows:
            row["created_at"] = "not-a-utc-timestamp"
        write_events(root, rows)
        write_evidence_manifest(root)
        report = build_report(root)

        self.assertTrue(report["coherent"], report)
        self.assertFalse(report["comparison_readiness"]["comparison_eligible"])
        self.assertEqual(
            report["comparison_readiness"]["gates"]["measurement_temporal_coverage"][
                "reason"
            ],
            "measurement_event_timestamps_incomplete",
        )

    def test_no_submit_artifact_must_join_required_manifest_evidence(self) -> None:
        root = self.base / "no-submit-unpreserved-artifact"
        rows = build_eligible_runtime(root)
        configure_no_submit_chain(
            root,
            rows,
            artifact_reference="evidence/unpreserved-proof.txt",
            evidence_root="evidence/plan.txt",
        )

        report = build_report(root)

        self.assertTrue(report["coherent"], report)
        self.assertFalse(report["comparison_readiness"]["comparison_eligible"])
        self.assertEqual(
            report["comparison_readiness"]["gates"]["evidence_completeness"][
                "reason"
            ],
            "evidence_manifest_no_submit_artifact_missing",
        )

    def test_value_only_no_submit_has_no_terminal_artifact_requirement(self) -> None:
        root = self.base / "no-submit-value-only"
        rows = build_eligible_runtime(root)
        configure_no_submit_chain(
            root,
            rows,
            artifact_reference="",
            exact_value="fixture no-submit value",
        )

        report = build_report(root)

        self.assertTrue(report["coherent"], report)
        self.assertTrue(report["comparison_readiness"]["comparison_eligible"], report)
        self.assertEqual(
            report["evidence"]["terminal_evidence_root"]["references"], 1
        )
        output = self.base / "no-submit-value-only.json"
        self.assertEqual(compare_main([str(root), str(root), "--output", str(output)]), 0)
        self.assertTrue(output.is_file())

    def test_value_only_no_submit_rejects_substituted_plan_or_terminal_root(self) -> None:
        def configure(root: Path) -> tuple[list[dict[str, object]], str]:
            rows = build_eligible_runtime(root)
            configure_no_submit_chain(
                root,
                rows,
                artifact_reference="",
                exact_value="fixture no-submit value",
            )
            plan = next(row for row in rows if row["event_id"] == "plan")
            payload = plan["payload"]
            assert isinstance(payload, dict)
            plan_path = payload["plan_path"]
            assert isinstance(plan_path, str)
            return rows, plan_path

        substituted_root = self.base / "no-submit-value-only-substituted-plan"
        _rows, substituted_path = configure(substituted_root)
        (substituted_root / substituted_path).write_text("{}\n", encoding="utf-8")
        write_evidence_manifest(
            substituted_root,
            no_submit_plans={"plan-one"},
            no_submit_evidence_roots={"plan-one": substituted_path},
        )
        substituted = build_report(substituted_root)

        self.assertTrue(substituted["coherent"], substituted)
        self.assertFalse(substituted["comparison_readiness"]["comparison_eligible"])
        self.assertEqual(
            substituted["comparison_readiness"]["gates"]["evidence_completeness"][
                "reason"
            ],
            "evidence_manifest_no_submit_sealed_plan_mismatch",
        )

        root_substitution = self.base / "no-submit-value-only-root-substitution"
        root_rows, root_plan_path = configure(root_substitution)
        terminal = next(row for row in root_rows if row["event_id"] == "terminal")
        terminal_payload = terminal["payload"]
        assert isinstance(terminal_payload, dict)
        terminal_payload["evidence_root"] = "evidence/plan.txt"
        write_events(root_substitution, root_rows)
        write_evidence_manifest(
            root_substitution,
            no_submit_plans={"plan-one"},
            no_submit_evidence_roots={"plan-one": root_plan_path},
        )
        root_report = build_report(root_substitution)

        self.assertTrue(root_report["coherent"], root_report)
        self.assertFalse(root_report["comparison_readiness"]["comparison_eligible"])
        self.assertEqual(
            root_report["comparison_readiness"]["gates"]["evidence_completeness"][
                "reason"
            ],
            "evidence_manifest_no_submit_sealed_plan_mismatch",
        )

    def test_repeated_candidate_must_name_its_own_retry_parent(self) -> None:
        parent_a = "a" * 64
        parent_b = "b" * 64
        candidate_a = "c" * 64
        candidate_b = "d" * 64
        rows = [
            event(
                1,
                "rejection-a",
                "execution.rejected",
                {
                    "proposal_id": "proposal-a",
                    "objective_id": "objective-one",
                    "retry": {
                        "fingerprint": parent_a,
                        "candidate_identity_sha256": candidate_a,
                    },
                },
            ),
            event(
                2,
                "rejection-b",
                "execution.rejected",
                {
                    "proposal_id": "proposal-b",
                    "objective_id": "objective-one",
                    "retry": {
                        "fingerprint": parent_b,
                        "candidate_identity_sha256": candidate_b,
                    },
                },
            ),
            event(
                3,
                "repeated-b-wrong-parent",
                "proposal.created",
                {
                    "proposal_id": "proposal-b-again-wrong",
                    "objective_id": "objective-one",
                    "candidate_identity_sha256": candidate_b,
                    "parent_rejection_fingerprint": parent_a,
                    "discriminator": "repeated B names A",
                },
            ),
            event(
                4,
                "repeated-b-correct-parent",
                "proposal.created",
                {
                    "proposal_id": "proposal-b-again-correct",
                    "objective_id": "objective-one",
                    "candidate_identity_sha256": candidate_b,
                    "parent_rejection_fingerprint": parent_b,
                    "discriminator": "repeated B names B",
                },
            ),
        ]

        lineage = telemetry_module.summarize_scoring_proposal_retry_lineage(rows)

        self.assertEqual(lineage["proposals_with_valid_parent_lineage"], 1)
        self.assertEqual(lineage["proposals_with_known_parent_fingerprint"], 1)
        self.assertEqual(lineage["proposals_with_unknown_parent_fingerprint"], 1)
        self.assertEqual(lineage["same_candidate_follow_up_denominator"], 1)

    def test_allowance_regrant_preserves_operator_provenance(self) -> None:
        origin_payload = {
            "authorization_id": "allowance-one",
            "mode": "allowance",
            "action_kind": "flag",
            "remaining": 2,
            "reason": "fixture allowance",
            "granted_at": "2026-08-28T00:00:01Z",
            "stop_generation": 0,
            "policy_generation": 0,
        }
        consumption_payload = {
            **origin_payload,
            "remaining": 1,
            "consumed_for_plan": "plan-one",
            "consumed_at": "2026-08-28T00:00:02Z",
        }
        origin = event(
            1, "allowance-origin", "authorization.granted", origin_payload, actor="operator"
        )
        consumption = event(
            2,
            "allowance-consumed",
            "authorization.consumed",
            consumption_payload,
            actor="executor",
        )
        regrant = event(
            3,
            "allowance-regranted",
            "authorization.granted",
            consumption_payload,
            actor="executor",
        )

        self.assertTrue(
            telemetry_module._authorization_grant_provenance_valid(
                [origin, consumption, regrant], regrant
            )
        )

        forged = copy.deepcopy(regrant)
        forged["event_id"] = "allowance-forged"
        forged["seq"] = 2
        self.assertFalse(
            telemetry_module._authorization_grant_provenance_valid(
                [origin, forged], forged
            )
        )

        coordinator_payload = {
            **origin_payload,
            "authorization_id": "allowance-coordinator",
            "authority_source": "operator_configured_automation",
        }
        coordinator_origin = event(
            4,
            "allowance-coordinator-origin",
            "authorization.granted",
            coordinator_payload,
            actor="coordinator",
        )
        self.assertTrue(
            telemetry_module._authorization_grant_provenance_valid(
                [coordinator_origin], coordinator_origin
            )
        )
        missing_source = copy.deepcopy(coordinator_origin)
        missing_source["payload"].pop("authority_source")
        self.assertFalse(
            telemetry_module._authorization_grant_provenance_valid(
                [missing_source], missing_source
            )
        )

    def test_terminal_jobs_use_unique_final_state_and_refuse_conflicts(self) -> None:
        root = self.base / "job-terminal-conflict"
        rows = build_eligible_runtime(root)
        original = next(row for row in rows if row["event_id"] == "job-closed")
        duplicate = copy.deepcopy(original)
        duplicate["event_id"] = "job-cancelled-after-close"
        duplicate["event_type"] = "job.cancelled"
        duplicate["seq"] = len(rows) + 1
        duplicate["created_at"] = "2026-08-28T00:00:20Z"
        rows.append(duplicate)
        write_events(root, rows)
        write_evidence_manifest(root)

        report = build_report(root)
        resources = report["measurement"]["resources"]

        self.assertEqual(resources["terminal_job_transition_count"], 2)
        self.assertEqual(resources["terminal_jobs"], 1)
        self.assertTrue(report["coherent"], report)
        self.assertFalse(report["comparison_readiness"]["comparison_eligible"])
        self.assertEqual(
            report["comparison_readiness"]["gates"][
                "queue_stop_resource_applicability"
            ]["components"]["resources"]["reason"],
            "terminal_job_state_conflict",
        )

        duplicate_root = self.base / "job-terminal-duplicate"
        duplicate_rows = build_eligible_runtime(duplicate_root)
        duplicate_original = next(
            row for row in duplicate_rows if row["event_id"] == "job-closed"
        )
        duplicate_close = copy.deepcopy(duplicate_original)
        duplicate_close["event_id"] = "job-closed-duplicate"
        duplicate_close["seq"] = len(duplicate_rows) + 1
        duplicate_close["created_at"] = "2026-08-28T00:00:20Z"
        duplicate_rows.append(duplicate_close)
        write_events(duplicate_root, duplicate_rows)
        write_evidence_manifest(duplicate_root)
        duplicate_report = build_report(duplicate_root)

        self.assertEqual(
            duplicate_report["measurement"]["resources"]["terminal_job_transition_count"],
            2,
        )
        self.assertEqual(
            duplicate_report["measurement"]["resources"]["terminal_jobs"], 1
        )
        self.assertTrue(
            duplicate_report["comparison_readiness"]["comparison_eligible"],
            duplicate_report,
        )

        missing_id_root = self.base / "job-terminal-missing-id"
        missing_id_rows = build_eligible_runtime(missing_id_root)
        missing_job = next(row for row in missing_id_rows if row["event_id"] == "job-closed")
        missing_payload = missing_job["payload"]
        assert isinstance(missing_payload, dict)
        del missing_payload["job_id"]
        write_events(missing_id_root, missing_id_rows)
        write_evidence_manifest(missing_id_root)
        missing_id_report = build_report(missing_id_root)

        self.assertFalse(missing_id_report["comparison_readiness"]["comparison_eligible"])
        self.assertEqual(
            missing_id_report["comparison_readiness"]["gates"][
                "queue_stop_resource_applicability"
            ]["components"]["resources"]["reason"],
            "terminal_job_identifier_incomplete",
        )

    def test_authorization_grants_require_operator_reason_and_ordered_time(self) -> None:
        def grant(rows: list[dict[str, object]]) -> dict[str, object]:
            record = next(row for row in rows if row["event_id"] == "authorization-granted")
            payload = record["payload"]
            assert isinstance(payload, dict)
            return payload

        def grant_record(rows: list[dict[str, object]]) -> dict[str, object]:
            return next(row for row in rows if row["event_id"] == "authorization-granted")

        def actor(rows: list[dict[str, object]]) -> None:
            grant_record(rows)["actor"] = "solver-one"

        def empty_reason(rows: list[dict[str, object]]) -> None:
            grant(rows)["reason"] = ""

        def missing_time(rows: list[dict[str, object]]) -> None:
            del grant(rows)["granted_at"]

        def late_time(rows: list[dict[str, object]]) -> None:
            grant(rows)["granted_at"] = "2026-08-28T00:00:09Z"

        for name, mutate in (
            ("actor", actor),
            ("reason", empty_reason),
            ("time", missing_time),
            ("late", late_time),
        ):
            with self.subTest(name=name):
                root = self.base / f"grant-{name}"
                rows = build_eligible_runtime(root)
                mutate(rows)
                write_events(root, rows)
                write_evidence_manifest(root)

                report = build_report(root)

                self.assertTrue(report["coherent"], report)
                self.assertFalse(report["comparison_readiness"]["comparison_eligible"])
                self.assertEqual(
                    report["comparison_readiness"]["gates"][
                        "final_scoring_chain_lineage"
                    ]["reason"],
                    "scoring_chain_authorization_grant_mismatch",
                )

    def test_changed_candidate_retry_recomputes_parent_and_remains_eligible(self) -> None:
        root = self.base / "changed-candidate-follow-up"
        rows = build_eligible_runtime(root)
        parent_proposal = next(row for row in rows if row["event_id"] == "proposal")
        parent_plan = next(row for row in rows if row["event_id"] == "plan")
        parent_terminal = next(row for row in rows if row["event_id"] == "terminal")
        parent_payload = parent_proposal["payload"]
        parent_plan_payload = parent_plan["payload"]
        parent_terminal_payload = parent_terminal["payload"]
        assert isinstance(parent_payload, dict)
        assert isinstance(parent_plan_payload, dict)
        assert isinstance(parent_terminal_payload, dict)

        parent_terminal["event_type"] = "execution.rejected"
        parent_terminal_payload["status"] = "rejected"
        parent_terminal_payload["verdict"] = {
            "verdict": "rejected",
            "scorer_truth": "rejected",
        }
        verdict_sha256 = hashlib.sha256(
            canonical_json(parent_terminal_payload["verdict"]).encode("utf-8")
        ).hexdigest()
        parent_fingerprint = hashlib.sha256(
            canonical_json(
                {
                    "candidate_identity_sha256": parent_payload[
                        "candidate_identity_sha256"
                    ],
                    "objective_id": parent_plan_payload["objective_id"],
                    "terminal_state": "rejected",
                    "verdict_sha256": verdict_sha256,
                }
            ).encode("utf-8")
        ).hexdigest()
        parent_terminal_payload["retry"] = {
            "fingerprint": parent_fingerprint,
            "candidate_identity_sha256": parent_payload["candidate_identity_sha256"],
            "normalized_value_sha256": parent_payload["normalized_value_sha256"],
            "verdict_sha256": verdict_sha256,
            "terminal_state": "rejected",
        }

        changed_value = "materially-changed-value"
        attempt_scope_sha256 = str(parent_payload["attempt_scope_sha256"])
        changed_normalized_sha256 = hashlib.sha256(changed_value.encode("utf-8")).hexdigest()
        changed_candidate_sha256 = hashlib.sha256(
            canonical_json(
                {
                    "action_kind": "flag",
                    "attempt_scope_sha256": attempt_scope_sha256,
                    "normalized_value_sha256": changed_normalized_sha256,
                    "objective_id": "objective-one",
                }
            ).encode("utf-8")
        ).hexdigest()
        proposal_two = copy.deepcopy(parent_payload)
        proposal_two.update(
            {
                "proposal_id": "proposal-two",
                "solver": "solver-two",
                "exact_value": changed_value,
                "value_sha256": hashlib.sha256(changed_value.encode("utf-8")).hexdigest(),
                "normalized_value_sha256": changed_normalized_sha256,
                "candidate_identity_sha256": changed_candidate_sha256,
                "source": "evidence/plan.txt",
                "rationale": "materially changed candidate",
                "agent_attempt_id": "attempt-two",
                "parent_rejection_fingerprint": parent_fingerprint,
                "discriminator": "the candidate value changed after the rejection",
                "created_at": "2026-08-28T00:00:14Z",
            }
        )
        review_two = {
            "proposal_id": "proposal-two",
            "verdict": "approved",
            "reviewer": "reviewer-two",
            "reason": "independent changed-candidate review",
            "verifier_report": "",
            "reviewed_at": "2026-08-28T00:00:15Z",
            "stop_generation": 0,
            "policy_generation": 0,
        }
        plan_two = copy.deepcopy(parent_plan_payload)
        plan_two.update(
            {
                "plan_id": "plan-two",
                "proposal_id": "proposal-two",
                "created_at": "2026-08-28T00:00:16Z",
            }
        )
        envelope = plan_two["envelope"]
        predicates = plan_two["predicates"]
        assert isinstance(envelope, dict)
        assert isinstance(predicates, dict)
        envelope.update({"proposal_id": "proposal-two", "exact_value": changed_value})
        predicates.update(
            {
                "proposal_event_id": "proposal-two",
                "review_event_id": "review-two",
                "authorization_id": "authorization-two",
            }
        )
        plan_two["plan_sha256"] = hashlib.sha256(
            canonical_json(
                {
                    key: value
                    for key, value in plan_two.items()
                    if key not in {"plan_path", "plan_sha256"}
                }
            ).encode("utf-8")
        ).hexdigest()

        rows = [
            row
            for row in rows
            if row["event_type"] not in {"control.stop", "job.closed"}
        ]
        rows.extend(
            [
                event(
                    14,
                    "agent-running-two",
                    "agent.running",
                    {
                        "agent_id": "agent-two",
                        "agent_attempt_id": "attempt-two",
                        "objective_id": "objective-one",
                        "role": "solver",
                    },
                    second=14,
                ),
                event(15, "proposal-two", "proposal.created", proposal_two, second=15),
                event(16, "review-two", "review.recorded", review_two, second=16),
                event(
                    17,
                    "plan-two",
                    "execution.planned",
                    {**plan_two, "plan_path": "state/execution_plans/plan-two.json"},
                    second=17,
                ),
                event(
                    18,
                    "authorization-granted-two",
                    "authorization.granted",
                    {
                        "authorization_id": "authorization-two",
                        "mode": "exact",
                        "proposal_id": "proposal-two",
                        "action_kind": "flag",
                        "remaining": 1,
                        "reason": "fixture changed-candidate authorization",
                        "granted_at": "2026-08-28T00:00:18Z",
                        "stop_generation": 0,
                        "policy_generation": 0,
                    },
                    actor="operator",
                    second=18,
                ),
                event(
                    19,
                    "authorization-consumed-two",
                    "authorization.consumed",
                    {
                        "authorization_id": "authorization-two",
                        "consumed_for_plan": "plan-two",
                        "proposal_id": "proposal-two",
                        "action_kind": "flag",
                        "mode": "exact",
                        "remaining": 0,
                        "consumed_at": "2026-08-28T00:00:19Z",
                        "stop_generation": 0,
                        "policy_generation": 0,
                    },
                    second=19,
                ),
                event(
                    20,
                    "execution-started-two",
                    "execution.started",
                    {
                        "plan_id": "plan-two",
                        "proposal_id": "proposal-two",
                        "objective_id": "objective-one",
                        "action_kind": "flag",
                        "stop_generation": 0,
                        "policy_generation": 0,
                        "scope_generation": 0,
                        "review_event_id": "review-two",
                        "authorization_id": "authorization-two",
                        "started_at": "2026-08-28T00:00:20Z",
                    },
                    second=20,
                ),
                event(
                    21,
                    "terminal-two",
                    "execution.completed",
                    {
                        "plan_id": "plan-two",
                        "proposal_id": "proposal-two",
                        "objective_id": "objective-one",
                        "action_kind": "flag",
                        "status": "completed",
                        "response_path": "evidence/response.json",
                        "evidence_root": "evidence",
                        "verdict": {"verdict": "accepted", "scorer_truth": "accepted"},
                        "completed_at": "2026-08-28T00:00:21Z",
                    },
                    second=21,
                ),
                event(
                    22,
                    "agent-closed-two",
                    "agent.closed",
                    {
                        "agent_id": "agent-two",
                        "agent_attempt_id": "attempt-two",
                        "objective_id": "objective-one",
                    },
                    second=22,
                ),
                event(
                    23,
                    "outcome-two",
                    "outcome.recorded",
                    {
                        "outcome_id": "outcome-two",
                        "outcome_type": "supported_finding",
                        "agent_id": "agent-two",
                        "agent_attempt_id": "attempt-two",
                        "objective_id": "objective-one",
                    },
                    second=23,
                ),
                event(
                    24,
                    "stop",
                    "control.stop",
                    {
                        "reason": "fixture changed-candidate closeout",
                        "generation": 1,
                        "watcher_epoch": 1,
                        "requested_at": "2026-08-28T00:00:24Z",
                    },
                    actor="operator",
                    second=24,
                ),
                event(
                    25,
                    "job-closed",
                    "job.closed",
                    {
                        "job_id": "job-one",
                        "owner_token": "owner-one",
                        "closed_at": "2026-08-28T00:00:25Z",
                        "resource_summary": {
                            "cpu_seconds": 0.5,
                            "rss_bytes": 1024,
                            "peak_rss_bytes": 2048,
                        },
                    },
                    second=25,
                ),
            ]
        )
        for row in rows:
            if row["event_id"] in {"stop", "job-closed"}:
                row["generation"] = 1
        write_events(root, rows)
        write_evidence_manifest(root, ("plan-one", "plan-two"))

        report = build_report(root)

        self.assertTrue(report["coherent"], report)
        self.assertTrue(report["comparison_readiness"]["comparison_eligible"], report)

    def test_wrapper_accepts_eligible_reports(self) -> None:
        left_root = self.base / "wrapper-left"
        right_root = self.base / "wrapper-right"
        build_eligible_runtime(left_root)
        build_eligible_runtime(right_root, terminal_second=8)
        output = self.base / "wrapper-comparison.json"

        completed = subprocess.run(
            [
                str(ROOKERY_ROOT / "bin" / "telemetry-compare"),
                str(left_root),
                str(right_root),
                "--output",
                str(output),
            ],
            text=True,
            capture_output=True,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            timeout=30,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(output.is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
