from __future__ import annotations

import datetime as dt
from typing import Any

from .intake import platform_solver_eligibility
from .util import UTC, parse_iso


_INELIGIBLE_SCORE = -999.0
_INELIGIBLE_TIER = 9
_SOLVER_INELIGIBILITY_REASONS = {
    "hidden",
    "intake_invalid",
    "intake_partial",
    "intake_pending",
    "locked",
    "manual",
    "operator_only",
    "policy_blocked",
    "solved",
    "unsupported",
    "unavailable",
}


def _solver_eligibility(challenge: dict[str, Any]) -> tuple[bool, str]:
    """Return a stable, value-free foreground eligibility decision."""

    if challenge.get("solver_eligible") is False:
        reason = str(challenge.get("solver_ineligible_reason") or "").casefold()
        if reason not in _SOLVER_INELIGIBILITY_REASONS:
            reason = "solver_ineligible"
        return False, reason
    platform = platform_solver_eligibility(challenge)
    if not platform["ready"]:
        return False, str(platform.get("reason") or "solver_ineligible")
    if "intake_state" in challenge:
        intake_state = str(challenge.get("intake_state") or "").casefold()
        if intake_state != "complete":
            return False, {
                "pending": "intake_pending",
                "partial": "intake_partial",
            }.get(intake_state, "intake_invalid")
    return True, ""


def _normalize(value: float, maximum: float) -> float:
    return 0.0 if maximum <= 0 else max(0.0, min(1.0, value / maximum))


def rank_challenges(
    challenges: list[dict[str, Any]],
    manifest: dict[str, Any],
    *,
    coordination: dict[str, dict[str, Any]] | None = None,
    source_event_count: int | None = None,
    source_stop_generation: int | None = None,
    now: dt.datetime | None = None,
) -> list[dict[str, Any]]:
    now = now or dt.datetime.now(UTC)
    cfg = manifest.get("priority", {})
    weights = cfg.get("weights", {})
    max_points = max([float(c.get("points", 0) or 0) for c in challenges] + [1.0])
    max_solves = max([float(c.get("solve_count", 0) or 0) for c in challenges] + [1.0])
    ranked = []
    for challenge in challenges:
        solver_eligible, solver_ineligible_reason = _solver_eligibility(challenge)
        challenge_id = str(challenge.get("id", ""))
        history = (coordination or {}).get(challenge_id, {})
        released = parse_iso(challenge.get("released_at"))
        freshness = 0.0
        if released:
            age_h = max(0.0, (now - released).total_seconds() / 3600)
            freshness = max(0.0, 1.0 - min(age_h, 48.0) / 48.0)
        value = _normalize(float(challenge.get("points", 0) or 0), max_points)
        low_solve = 1.0 - _normalize(
            float(challenge.get("solve_count", 0) or 0), max_solves
        )
        effort = float(challenge.get("expected_effort", 0.5) or 0.5)
        maturity = float(challenge.get("evidence_maturity", 0.0) or 0.0)
        dependency = float(challenge.get("dependency_readiness", 1.0) or 0.0)
        infra = float(challenge.get("infrastructure_readiness", 1.0) or 0.0)
        lane_age = float(challenge.get("lane_age_hours", 0.0) or 0.0)
        lane_age = min(lane_age / 24.0, 1.0)
        override = float(challenge.get("operator_override", 0.0) or 0.0)
        features = {
            "release_freshness": freshness,
            "value": value,
            "low_solve_count": low_solve,
            "expected_effort": effort,
            "evidence_maturity": maturity,
            "dependency_readiness": dependency,
            "infrastructure_readiness": infra,
            "lane_age": lane_age,
            "operator_override": override,
        }
        score = sum(float(weights.get(k, 0.0)) * v for k, v in features.items())
        low_progress_count = int(history.get("low_progress_outcome_count", 0) or 0)
        diminishing_return_penalty = min(low_progress_count, 4) * float(
            cfg.get("low_progress_penalty", 0.25) or 0.0
        )
        score -= diminishing_return_penalty
        frontier_state = str(history.get("frontier_state") or "")
        if not frontier_state:
            frontier_state = (
                "solved"
                if challenge.get("solved") is True
                or challenge.get("classification") == "solved"
                else "unprojected"
            )
        if challenge.get("classification") == "parked":
            frontier_state = "parked"
        elif challenge.get("classification") == "blocked":
            frontier_state = "stuck"
        frontier_tier = {
            "untouched": 0,
            "attempted": 1,
            "stuck": 2,
            "routed": 3,
            "exploring": 4,
            "parked": 5,
            "solved": 9,
            "unprojected": 1,
        }.get(frontier_state, 2)
        foreground_eligible = frontier_state not in {
            "routed",
            "exploring",
            "parked",
            "solved",
        }
        if not solver_eligible:
            score = _INELIGIBLE_SCORE
            frontier_tier = _INELIGIBLE_TIER
            foreground_eligible = False
        elif frontier_state in {"exploring", "parked"}:
            # Keep the row visible while excluding it from foreground selection.
            score = _INELIGIBLE_SCORE
        contributions = sorted(
            ((k, float(weights.get(k, 0.0)) * v) for k, v in features.items()),
            key=lambda x: abs(x[1]),
            reverse=True,
        )
        reason = ", ".join(f"{k}={v:+.2f}" for k, v in contributions[:3])
        if diminishing_return_penalty:
            reason += f"; low_progress_penalty=-{diminishing_return_penalty:.2f}"
        reason += f"; frontier_state={frontier_state}"
        if solver_ineligible_reason:
            reason += f"; ineligible={solver_ineligible_reason}"
        equivalent_trace_count = max(
            int(challenge.get("equivalent_trace_count", 0) or 0),
            int(history.get("equivalent_trace_count", 0) or 0),
        )
        if equivalent_trace_count >= 3:
            reason += "; next assignment must use a named discriminating test"
        row = {
            **challenge,
            "priority_score": round(score, 6),
            "priority_reason": reason,
            "policy_generation": manifest.get("policy_generation", 0),
            "frontier_state": frontier_state,
            "frontier_tier": frontier_tier,
            "foreground_eligible": foreground_eligible,
            "solver_eligible": solver_eligible,
            "solver_ineligible_reason": solver_ineligible_reason,
            "untouched": bool(history.get("untouched", False)),
            "attempt_count": int(history.get("attempt_count", 0) or 0),
            "outcome_count": int(history.get("outcome_count", 0) or 0),
            "low_progress_outcome_count": low_progress_count,
            "has_current_continuation": bool(
                history.get("has_current_continuation", False)
            ),
            "parked_campaign_ids": list(history.get("parked_campaign_ids", [])),
            "park_reason": str(
                history.get("park_reason")
                or challenge.get("park_reason")
                or challenge.get("return_condition")
                or ""
            ),
            "equivalent_trace_count": equivalent_trace_count,
            "required_next_method": "distinct-method-review"
            if equivalent_trace_count >= 3
            else challenge.get("required_next_method", ""),
        }
        if source_event_count is not None:
            row["source_event_count"] = source_event_count
        if source_stop_generation is not None:
            row["source_stop_generation"] = source_stop_generation
        ranked.append(
            row
        )
    return sorted(
        ranked,
        key=lambda c: (
            int(c["frontier_tier"]),
            -float(c["priority_score"]),
            str(c.get("id", "")),
        ),
    )


def frontier_projection_staleness(
    ranked: list[dict[str, Any]],
    *,
    canonical_event_count: int,
    current_stop_generation: int,
) -> dict[str, Any]:
    """Explain whether a cached frontier can represent current canonical state."""

    reasons: list[str] = []
    event_counts = {row.get("source_event_count") for row in ranked}
    generations = {row.get("source_stop_generation") for row in ranked}
    if not ranked:
        if canonical_event_count:
            reasons.append("frontier_missing")
    elif None in event_counts or len(event_counts) != 1:
        reasons.append("source_event_count_missing_or_inconsistent")
    elif event_counts != {canonical_event_count}:
        reasons.append("canonical_event_count_changed")
    if ranked and (None in generations or len(generations) != 1):
        reasons.append("source_stop_generation_missing_or_inconsistent")
    elif ranked and generations != {current_stop_generation}:
        reasons.append("stop_generation_changed")
    return {
        "stale": bool(reasons),
        "reasons": reasons,
        "canonical_event_count": canonical_event_count,
        "current_stop_generation": current_stop_generation,
    }
