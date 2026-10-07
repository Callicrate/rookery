from __future__ import annotations

from pathlib import Path
from typing import Any

from rookery.portable.adapters import Adapter, CapabilityHealth, normalized_snapshot
from rookery.portable.util import atomic_write_json, load_json
from rookery.verdict_parser import parse_verdict


class FixtureAdapter(Adapter):
    id = "fixture"

    def _fixture_path(self) -> Path:
        raw = str(self.config.get("fixture_path") or "adapters/fixture/event.json")
        path = Path(raw)
        return path if path.is_absolute() else self.root / path

    def sync(self) -> dict[str, Any]:
        path = self._fixture_path()
        data = load_json(path, {})
        if not isinstance(data, dict):
            data = {}
        capabilities = [
            CapabilityHealth(
                name,
                value.get("availability", "available"),
                value.get("health", "healthy"),
                value.get("freshness", "fixture"),
                value.get("read_write_scope", "read-only"),
                tuple(value.get("permitted_mutations", [])),
                value.get("detail", ""),
            )
            for name, value in (data.get("capabilities") or {}).items()
        ]
        return normalized_snapshot(
            self.id,
            capabilities,
            data.get("challenges", []),
            releases=data.get("releases", []),
            collaboration=data.get("collaboration", {}),
            session=data.get("session", {}),
            artifact=str(path),
        )

    def execute_action(self, envelope: dict[str, Any], evidence_root: Path) -> dict[str, Any]:
        data = load_json(self._fixture_path(), {}) or {}
        value = envelope.get("exact_value", "")
        objective = str(envelope.get("objective_id", ""))
        rules = data.get("verdicts", {})
        verdict = rules.get(
            f"{objective}:{value}",
            rules.get(str(value), rules.get("default", {"correct": False, "message": "fixture rejected"})),
        )
        response = {"http_status": 200, "data": verdict, "request": envelope}
        evidence_root.mkdir(parents=True, exist_ok=True)
        atomic_write_json(evidence_root / "request.json", envelope)
        atomic_write_json(evidence_root / "response.json", response)
        return {
            "response": response,
            "response_path": str(evidence_root / "response.json"),
            "verdict": parse_verdict(response).to_dict(),
        }
