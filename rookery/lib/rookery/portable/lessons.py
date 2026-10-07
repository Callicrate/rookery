from __future__ import annotations

from pathlib import Path
from typing import Any

from .store import EventStore
from .util import atomic_write_text, compact_now, iso_now


def create_lessons_document(
    store: EventStore,
    root: Path,
    *,
    reason: str,
    actor: str = "coordinator",
) -> dict[str, Any]:
    """Create exactly one improvements-only lessons document per stop generation.

    This document is deliberately not a run report. It is a durable input to the
    next Rookery release: add/change/remove/simplify decisions, agent/tool/protocol
    changes, anti-overfit notes, and regression ideas.
    """
    generation = store.current_stop_generation()
    existing = [
        e
        for e in store.events("lessons.created")
        if int(e.get("generation", -1)) == generation
    ]
    if existing:
        payload = dict(existing[-1]["payload"])
        path = root / str(payload.get("path", ""))
        if path.exists():
            return {**payload, "reused": True}

    stamp = compact_now()
    release_version = (
        (root / "VERSION").read_text(encoding="utf-8", errors="replace").strip()
        if (root / "VERSION").is_file()
        else "unknown"
    )
    directory = root / "docs" / "retrospectives"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"lessons-learned-{stamp}.md"
    text = f"""# Lessons Learned {stamp}

## Scope

This document is only about reusable improvements to future Rookery releases. It must not become a run-status report, handoff, scoreboard summary, flag list, challenge solution narrative, or operator diary.

Stop trigger: `{reason}`

Rookery release: `{release_version}`

Use local evidence to support Rookery-level conclusions. Preserve exact evidence elsewhere. Treat subtraction as first-class: removing confusing tools, duplicated routes, stale assumptions, or overbearing protocol is as valuable as adding capability.

## Executive Summary

## Preserve

What worked well enough to keep, and why.

## Add

New capability justified by a demonstrated gap. Prefer the smallest distinct contract.

## Change

Existing behavior that should be altered, consolidated, or made more reliable.

## Remove Or Simplify

Concrete commands, aliases, protocols, prompts, state paths, agents, or assumptions that create more confusion than capability.

## Agent And Subagent Changes

Role boundaries, task-card changes, fallback behavior, specialization fit, coordination, and admission/removal decisions.

## Tooling Changes

Tools to add, replace, consolidate, or delete. Name the capability gap and the regression fixture.

## Protocol Changes

Changes to startup, solving, evidence, review, mutation, retry, stop, or recovery protocols.

## Operator Surface

Keep this short. The normal surface remains `./go`, `./go status`, and `./go stop` unless strong evidence justifies another public command.

## Evidence, State, And Review

Canonical state, projections, provenance, scorer truth, retries, queueing, and writeup behavior.

## Platform, Network, And Session Adapters

Generic adapter-contract changes and optional platform-specific improvements. Do not leak event-specific assumptions into the core.

## Anti-Overfit Notes

What should remain optional, fixture-specific, or not generalized.

## Subtractions Checklist

- [ ] Remove or demote confusing behavior.
- [ ] Remove redundant commands or duplicate state routes.
- [ ] Remove stale platform/event assumptions from generic prompts.
- [ ] Remove unnecessary policy text from lightweight scouts.
- [ ] Remove specialists whose capability is covered by a smaller existing contract.

## Recommended Next Rookery Changes

Prioritized, concrete, implementation-sized changes.

## Validation Ideas

Deterministic fixtures or checks that would prove the recommended changes.

"""
    atomic_write_text(path, text)
    payload = {
        "path": str(path.relative_to(root)),
        "stop_generation": generation,
        "reason": reason,
        "created_at": iso_now(),
        "release_version": release_version,
        "purpose": "future-Rookery-improvements-only",
    }
    store.append(
        "lessons.created",
        payload,
        actor=actor,
        generation=generation,
        event_id=f"lessons-created-generation-{generation}",
    )
    store.rebuild()
    return {**payload, "reused": False}
