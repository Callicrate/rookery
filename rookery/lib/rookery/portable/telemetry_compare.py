"""Bounded, descriptive comparison of two eligible telemetry reports."""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
import tempfile
from pathlib import Path
from typing import Any, Sequence

from .telemetry import REPORT_SCHEMA_VERSION, build_report
from .util import canonical_json

logger = logging.getLogger(__name__)

COMPARISON_SCHEMA_VERSION = "1"
MAX_OUTPUT_METRICS = 16
MAX_OUTCOME_CLASSES = 64
REQUIRED_GATES = frozenset(
    {
        "canonical_coherence",
        "command_scan",
        "command_lifecycle",
        "evidence_completeness",
        "baseline_binding",
        "final_scoring_chain_lineage",
        "typed_attempt_coverage",
        "queue_stop_resource_applicability",
    }
)


class TelemetryComparisonError(ValueError):
    """Raised when a report cannot safely participate in a comparison."""


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _validate_eligible_derived_report(report: dict[str, Any]) -> None:
    """Validate just the stable public report surface consumed below."""

    if (
        report.get("schema_version") != REPORT_SCHEMA_VERSION
        or report.get("report_kind") != "rookery.telemetry"
        or report.get("coherent") is not True
        or not isinstance(report.get("release_version"), str)
        or len(report["release_version"]) > 128
    ):
        raise TelemetryComparisonError("report_schema_invalid")
    readiness = report.get("comparison_readiness")
    if not isinstance(readiness, dict) or readiness.get("comparison_eligible") is not True:
        raise TelemetryComparisonError("report_not_comparison_eligible")
    gates = readiness.get("gates")
    if not isinstance(gates, dict) or not REQUIRED_GATES.issubset(gates):
        raise TelemetryComparisonError("report_schema_invalid")
    for name in REQUIRED_GATES:
        gate = gates[name]
        if not isinstance(gate, dict) or gate.get("passed") is not True:
            raise TelemetryComparisonError("report_not_comparison_eligible")
    canonical = report.get("canonical")
    if not isinstance(canonical, dict) or not _is_int(canonical.get("jsonl_rows")):
        raise TelemetryComparisonError("report_schema_invalid")
    if canonical["jsonl_rows"] < 0:
        raise TelemetryComparisonError("report_schema_invalid")
    if not isinstance(report.get("measurement"), dict) or not isinstance(report.get("events"), dict):
        raise TelemetryComparisonError("report_schema_invalid")


def _binding(report: dict[str, Any]) -> dict[str, Any]:
    gate = report["comparison_readiness"]["gates"]["baseline_binding"]
    binding = gate.get("binding")
    if not isinstance(binding, dict):
        raise TelemetryComparisonError("report_baseline_binding_invalid")
    if not all(
        _valid_sha256(binding.get(name))
        for name in ("baseline_sha256", "configuration_digest", "launch_binding_sha256")
    ) or not isinstance(binding.get("release_version"), str):
        raise TelemetryComparisonError("report_baseline_binding_invalid")
    generations = binding.get("generations")
    if not isinstance(generations, dict) or any(
        not _is_int(generations.get(name)) or generations[name] < 0
        for name in ("policy", "scope", "stop")
    ):
        raise TelemetryComparisonError("report_baseline_binding_invalid")
    contract = binding.get("measurement_contract")
    if (
        not isinstance(contract, dict)
        or not isinstance(contract.get("queue_automation_enabled"), bool)
        or not isinstance(contract.get("provider_fields"), dict)
        or set(contract["provider_fields"]) != {"queue", "tokens", "usage"}
        or any(
            not isinstance(field, dict)
            or set(field) != {"availability"}
            or field.get("availability") not in {"available", "unavailable"}
            for field in contract["provider_fields"].values()
        )
    ):
        raise TelemetryComparisonError("report_baseline_binding_invalid")
    return binding


def _integer_at(value: Any, *path: str) -> int | None:
    current = value
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current if _is_int(current) and current >= 0 else None


def _number_at(value: Any, *path: str) -> float | None:
    current = value
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    if isinstance(current, bool) or not isinstance(current, (int, float)):
        return None
    numeric = float(current)
    return numeric if math.isfinite(numeric) and numeric >= 0 else None


def _coverage_metric(
    name: str,
    left_numerator: int | None,
    left_denominator: int | None,
    right_numerator: int | None,
    right_denominator: int | None,
) -> dict[str, Any] | None:
    if None in (left_numerator, left_denominator, right_numerator, right_denominator):
        return None
    assert left_numerator is not None
    assert left_denominator is not None
    assert right_numerator is not None
    assert right_denominator is not None
    if left_numerator > left_denominator or right_numerator > right_denominator:
        return None
    return {
        "kind": "coverage",
        "name": name,
        "left": {"denominator": left_denominator, "numerator": left_numerator},
        "right": {"denominator": right_denominator, "numerator": right_numerator},
        "numerator_delta": right_numerator - left_numerator,
        "denominator_delta": right_denominator - left_denominator,
        "absolute_delta": (
            right_numerator / right_denominator - left_numerator / left_denominator
            if left_denominator and right_denominator
            else None
        ),
    }


def _count_metric(name: str, left: int | None, right: int | None) -> dict[str, Any] | None:
    if left is None or right is None:
        return None
    return {
        "kind": "count",
        "name": name,
        "left": {"denominator": 1, "numerator": left},
        "right": {"denominator": 1, "numerator": right},
        "numerator_delta": right - left,
        "denominator_delta": 0,
        "absolute_delta": right - left,
    }


def _rate_metric(name: str, left: float | None, right: float | None) -> dict[str, Any] | None:
    if left is None or right is None:
        return None
    return {
        "kind": "rate",
        "name": name,
        "left": {"value": left},
        "right": {"value": right},
        "absolute_delta": right - left,
    }


def _latency_metric(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any] | None:
    left_values = left.get("measurement", {}).get("proposal_to_terminal_latency", {})
    right_values = right.get("measurement", {}).get("proposal_to_terminal_latency", {})
    if not isinstance(left_values, dict) or not isinstance(right_values, dict):
        return None
    left_latency = left_values.get("latency_seconds")
    right_latency = right_values.get("latency_seconds")
    if not isinstance(left_latency, dict) or not isinstance(right_latency, dict):
        return None
    left_count = _integer_at(left_latency, "count")
    right_count = _integer_at(right_latency, "count")
    left_denominator = _integer_at(left_values, "matched_terminal_denominator")
    right_denominator = _integer_at(right_values, "matched_terminal_denominator")
    left_p50 = _number_at(left_latency, "p50")
    right_p50 = _number_at(right_latency, "p50")
    left_p95 = _number_at(left_latency, "p95")
    right_p95 = _number_at(right_latency, "p95")
    if None in (
        left_count,
        right_count,
        left_denominator,
        right_denominator,
        left_p50,
        right_p50,
        left_p95,
        right_p95,
    ):
        return None
    assert left_count is not None and right_count is not None
    assert left_denominator is not None and right_denominator is not None
    assert left_p50 is not None and right_p50 is not None
    assert left_p95 is not None and right_p95 is not None
    if left_count > left_denominator or right_count > right_denominator:
        return None
    return {
        "kind": "latency_seconds",
        "name": "proposal_to_terminal_latency",
        "left": {
            "denominator": left_denominator,
            "numerator": left_count,
            "p50": left_p50,
            "p95": left_p95,
        },
        "right": {
            "denominator": right_denominator,
            "numerator": right_count,
            "p50": right_p50,
            "p95": right_p95,
        },
        "numerator_delta": right_count - left_count,
        "denominator_delta": right_denominator - left_denominator,
        "p50_delta": right_p50 - left_p50,
        "p95_delta": right_p95 - left_p95,
    }


def _operational_shape(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    gate = report["comparison_readiness"]["gates"]["queue_stop_resource_applicability"]
    components = gate.get("components") if isinstance(gate, dict) else None
    result: dict[str, dict[str, Any]] = {}
    if not isinstance(components, dict):
        return result
    for name in ("queue", "stop", "resources"):
        component = components.get(name)
        if not isinstance(component, dict):
            continue
        result[name] = {
            "applicable": component.get("applicable", True) is not False,
            "availability": component.get("availability"),
            **({"reason": component["reason"]} if isinstance(component.get("reason"), str) else {}),
        }
    return result


def _outcome_counts(report: dict[str, Any]) -> dict[str, int]:
    values = _integer_map_at(report, "events", "workflow", "final_terminal_outcomes")
    if values is None or len(values) > MAX_OUTCOME_CLASSES:
        return {}
    return values


def _integer_map_at(value: Any, *path: str) -> dict[str, int] | None:
    current = value
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    if not isinstance(current, dict):
        return None
    result: dict[str, int] = {}
    for name, count in current.items():
        if not isinstance(name, str) or not name or len(name) > 128 or not _is_int(count) or count < 0:
            return None
        result[name] = count
    return result


def _difference(left: Any, right: Any) -> dict[str, Any]:
    return {"different": left != right, "left": left, "right": right}


def _resource_applicable(report: dict[str, Any]) -> bool:
    shape = _operational_shape(report)
    return bool(shape.get("resources", {}).get("applicable"))


def _owned_local_resource_applicable(report: dict[str, Any]) -> bool:
    """Expose a local-process denominator only for an owned terminal-job cohort."""

    denominator = _integer_at(
        report,
        "measurement",
        "resources",
        "owned_coverage",
        "denominator_owned_terminal_jobs",
    )
    return _resource_applicable(report) and denominator is not None and denominator > 0


def _provider_availability(binding: dict[str, Any]) -> dict[str, str]:
    contract = binding["measurement_contract"]
    providers = contract["provider_fields"]
    return {
        name: str(providers[name]["availability"])
        for name in ("queue", "tokens", "usage")
    }


def _compare_eligible_derived_reports(
    left: dict[str, Any], right: dict[str, Any]
) -> dict[str, Any]:
    """Format two immediately derived reports; never use serialized report input.

    This helper validates local telemetry structure, not the identity or
    provenance of whoever produced a preserved runtime.
    """

    _validate_eligible_derived_report(left)
    _validate_eligible_derived_report(right)
    left_binding = _binding(left)
    right_binding = _binding(right)

    metrics = [
        _count_metric(
            "canonical_events",
            _integer_at(left, "canonical", "jsonl_rows"),
            _integer_at(right, "canonical", "jsonl_rows"),
        ),
        _coverage_metric(
            "command_lifecycle_pairing",
            _integer_at(left, "commands", "lifecycle", "paired_events"),
            _integer_at(left, "commands", "lifecycle", "requested"),
            _integer_at(right, "commands", "lifecycle", "paired_events"),
            _integer_at(right, "commands", "lifecycle", "requested"),
        ),
        _coverage_metric(
            "terminal_evidence_references",
            _integer_at(left, "evidence", "terminal_response_path", "present"),
            _integer_at(left, "evidence", "terminal_response_path", "references"),
            _integer_at(right, "evidence", "terminal_response_path", "present"),
            _integer_at(right, "evidence", "terminal_response_path", "references"),
        ),
        _coverage_metric(
            "typed_attempt_outcomes",
            _integer_at(left, "events", "agents", "terminal_attempts_with_outcome"),
            _integer_at(left, "events", "agents", "terminal_attempts"),
            _integer_at(right, "events", "agents", "terminal_attempts_with_outcome"),
            _integer_at(right, "events", "agents", "terminal_attempts"),
        ),
        _coverage_metric(
            "final_scoring_chain",
            _integer_at(left, "measurement", "proposal_to_terminal_latency", "matched_terminal_denominator"),
            _integer_at(left, "measurement", "proposal_to_terminal_latency", "terminal_denominator"),
            _integer_at(right, "measurement", "proposal_to_terminal_latency", "matched_terminal_denominator"),
            _integer_at(right, "measurement", "proposal_to_terminal_latency", "terminal_denominator"),
        ),
        (
            _coverage_metric(
                "owned_terminal_job_local_process_coverage",
                _integer_at(
                    left,
                    "measurement",
                    "resources",
                    "owned_coverage",
                    "numerator_owned_terminal_jobs_with_local_process_resource",
                ),
                _integer_at(
                    left,
                    "measurement",
                    "resources",
                    "owned_coverage",
                    "denominator_owned_terminal_jobs",
                ),
                _integer_at(
                    right,
                    "measurement",
                    "resources",
                    "owned_coverage",
                    "numerator_owned_terminal_jobs_with_local_process_resource",
                ),
                _integer_at(
                    right,
                    "measurement",
                    "resources",
                    "owned_coverage",
                    "denominator_owned_terminal_jobs",
                ),
            )
            if _owned_local_resource_applicable(left)
            and _owned_local_resource_applicable(right)
            else None
        ),
        _latency_metric(left, right),
        _rate_metric(
            "queue_bytes_per_event_hour",
            _number_at(left, "measurement", "queue_normalized_rates", "bytes_per_event_hour"),
            _number_at(right, "measurement", "queue_normalized_rates", "bytes_per_event_hour"),
        ),
        _rate_metric(
            "queue_lines_per_event_hour",
            _number_at(left, "measurement", "queue_normalized_rates", "lines_per_event_hour"),
            _number_at(right, "measurement", "queue_normalized_rates", "lines_per_event_hour"),
        ),
    ]
    metrics = [metric for metric in metrics if metric is not None][:MAX_OUTPUT_METRICS]
    return {
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "report_kind": "rookery.telemetry_comparison",
        "comparison_kind": "descriptive",
        "differences": {
            "baseline": _difference(
                left_binding["baseline_sha256"], right_binding["baseline_sha256"]
            ),
            "configuration": _difference(
                left_binding["configuration_digest"], right_binding["configuration_digest"]
            ),
            "release": _difference(left["release_version"], right["release_version"]),
            "provider_availability": _difference(
                _provider_availability(left_binding), _provider_availability(right_binding)
            ),
        },
        "confounders": {
            "event_window_seconds": _difference(
                _number_at(left, "measurement", "event_window", "duration_seconds"),
                _number_at(right, "measurement", "event_window", "duration_seconds"),
            ),
            "final_terminal_outcomes": _difference(
                _outcome_counts(left), _outcome_counts(right)
            ),
            "launch_generations": _difference(
                left_binding["generations"], right_binding["generations"]
            ),
            "operational_applicability": _difference(
                _operational_shape(left), _operational_shape(right)
            ),
            "queue_automation": _difference(
                left_binding["measurement_contract"]["queue_automation_enabled"],
                right_binding["measurement_contract"]["queue_automation_enabled"],
            ),
        },
        "metrics": metrics,
    }


def _stable_runtime_report(
    runtime_root: Path, source_root: str | Path | None = None
) -> tuple[Path, dict[str, Any]]:
    """Build the local report twice and refuse a runtime that changes in view.

    Equality is a bounded local-consistency check over two read-only passes. It
    does not establish that the runtime or its events were published by anyone.
    """

    root = runtime_root.resolve()
    if not root.is_dir():
        raise TelemetryComparisonError("runtime_root_invalid")
    first = build_report(root, source_root)
    second = build_report(root, source_root)
    if canonical_json(first) != canonical_json(second):
        raise TelemetryComparisonError("runtime_changed_during_analysis")
    return root, first


def compare_runtime_roots(
    left_runtime: Path,
    right_runtime: Path,
    *,
    left_source_root: str | Path | None = None,
    right_source_root: str | Path | None = None,
) -> tuple[dict[str, Any], Path, Path]:
    """Build and compare two locally consistent preserved runtime roots."""

    left_root, left = _stable_runtime_report(left_runtime, left_source_root)
    right_root, right = _stable_runtime_report(right_runtime, right_source_root)
    return _compare_eligible_derived_reports(left, right), left_root, right_root


def write_comparison(
    comparison: dict[str, Any], output: Path, left_runtime: Path, right_runtime: Path
) -> None:
    """Atomically publish outside both analyzed runtimes without modifying them."""

    target = output.resolve()
    for root in {left_runtime.resolve(), right_runtime.resolve()}:
        try:
            target.relative_to(root)
        except ValueError:
            continue
        raise TelemetryComparisonError("comparison_output_must_be_outside_runtimes")
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    temporary = Path(temporary_name)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(comparison, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the read-only telemetry comparison command."""

    parser = argparse.ArgumentParser(
        description="Build and compare two locally consistent preserved telemetry runtimes"
    )
    parser.add_argument("left_runtime", type=Path)
    parser.add_argument("right_runtime", type=Path)
    parser.add_argument(
        "--left-source-root",
        help="absolute deployed root used by left runtime evidence paths",
    )
    parser.add_argument(
        "--right-source-root",
        help="absolute deployed root used by right runtime evidence paths",
    )
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        comparison, left_root, right_root = compare_runtime_roots(
            arguments.left_runtime,
            arguments.right_runtime,
            left_source_root=arguments.left_source_root,
            right_source_root=arguments.right_source_root,
        )
        write_comparison(
            comparison, arguments.output, left_root, right_root
        )
    except (OSError, TelemetryComparisonError):
        logger.error("Unable to compare telemetry reports")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
