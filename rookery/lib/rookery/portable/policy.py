from __future__ import annotations

import json
import uuid
from typing import Any

from .store import EventStore
from .util import file_lock, iso_now

POLICY_KEYS = {
    "strategy",
    "priority",
    "scoring_cadence",
    "scoring_exceptions",
    "resource_scheduling",
    "browser_ownership",
    "collaboration_rules",
    "session_authority",
    "writeup_timing",
    "raw_shell_policy",
}


def set_policy(
    store: EventStore,
    key: str,
    value: Any,
    *,
    source: str,
    reason: str,
    actor: str = "coordinator",
) -> dict[str, Any]:
    if key not in POLICY_KEYS:
        raise ValueError(f"unsupported policy key: {key}")
    if not source or not reason:
        raise ValueError("policy source and reason are required")

    def tx(con):
        effective = None
        rows = con.execute(
            "SELECT event_id,payload_json FROM events WHERE event_type='policy.set' ORDER BY seq DESC"
        ).fetchall()
        for row in rows:
            candidate = json.loads(row["payload_json"])
            if candidate.get("key") == key:
                effective = {**candidate, "event_id": row["event_id"]}
                break
        if (
            effective
            and effective.get("value") == value
            and effective.get("source") == source
        ):
            return False
        generation = store.increment_meta_in_transaction(con, "policy_generation")
        stop_row = con.execute(
            "SELECT value FROM meta WHERE key='stop_generation'"
        ).fetchone()
        stop_generation = int(stop_row[0]) if stop_row else 0
        payload = {
            "policy_id": uuid.uuid4().hex,
            "key": key,
            "value": value,
            "source": source,
            "reason": reason,
            "generation": generation,
            "supersedes_event_id": effective.get("event_id", "") if effective else "",
            "recorded_at": iso_now(),
        }
        store.insert_in_transaction(
            con, "policy.set", payload, actor=actor, generation=stop_generation
        )
        return True

    # Policy generation is a dispatch predicate.  Share execution's mutation
    # barrier so a generation change cannot pass between validation and adapter
    # dispatch.
    with file_lock(store.root / "state" / "mutation.lock"):
        changed = store.transaction(tx)
    if not changed:
        return store.rebuild()["policy"]["effective"][key]
    return store.rebuild()["policy"]["effective"][key]


def effective_policy(store: EventStore) -> dict[str, Any]:
    return store.rebuild().get("policy", {})
