from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

from tests.rookery.support import ROOKERY_ROOT

LIBRARY = ROOKERY_ROOT / "lib"
if str(LIBRARY) not in sys.path:
    sys.path.insert(0, str(LIBRARY))

from rookery.portable.status import (  # noqa: E402
    _read_matching_current_activity,
    _reconciliation_debt_report_paths,
    render_status,
)
from rookery.portable.util import atomic_write_json, tree_hash  # noqa: E402


class StatusReconciliationDebtTests(unittest.TestCase):
    @staticmethod
    def _snapshot(paths: tuple[str, ...]) -> dict[str, object]:
        return {
            "status_truth": {
                "activity": {
                    "source": "matched_current_projection",
                    "reconciliation_debts": len(paths),
                    "reconciliation_debt_report_paths": paths,
                }
            }
        }

    def test_status_keeps_post_stop_debt_visible_after_resume_without_reading_report(self) -> None:
        report_path = "analysis/event-wide-closeout/REPORT.md"
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / report_path
            self.assertFalse(report.exists())
            rendered = render_status(self._snapshot((report_path,)))

        # The continuation audit persists this path after a stopped worker's
        # report arrives; status renders the path without opening that report.
        self.assertIn("reconciliation_debt=attempts=1 report_count=1", rendered)
        self.assertIn(f"report_paths={report_path}", rendered)
        self.assertIn("paths_truncated=false", rendered)

    def test_status_hides_malformed_debt_paths(self) -> None:
        private_path = "/private/should-not-render/REPORT.md"
        paths = _reconciliation_debt_report_paths([private_path])
        rendered = render_status(
            {
                "status_truth": {
                    "activity": {
                        "source": "matched_current_projection",
                        "reconciliation_debts": "unknown",
                        "reconciliation_debt_report_paths": paths,
                    }
                }
            }
        )

        self.assertIn(
            "reconciliation_debt=attempts=unknown report_count=unknown report_paths=unknown",
            rendered,
        )
        self.assertNotIn(private_path, rendered)

    @unittest.skipUnless(os.name == "posix", "private current projection fixture")
    def test_pure_current_projection_read_exposes_post_stop_debt_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            state.mkdir(mode=0o700)
            report_path = "analysis/event-wide-closeout/REPORT.md"
            atomic_write_json(
                state / "current.json",
                {
                    "event_count": 4,
                    "stop_generation": 2,
                    "stopped": False,
                    "agents": {},
                    "jobs": {},
                    "harvested_reports": {},
                    "continuation_audit": {
                        "unharvested_active": 0,
                        "unconsumed_handoffs": 0,
                        "reconciliation_debts": 1,
                        "reconciliation_debt_report_paths": [report_path],
                    },
                },
                mode=0o600,
            )
            before = tree_hash(root)
            activity = _read_matching_current_activity(
                root,
                {"event_count": 4, "stop_generation": 2, "stopped": False},
            )
            after = tree_hash(root)

        self.assertEqual(before, after)
        self.assertEqual(activity["reconciliation_debts"], 1)
        self.assertEqual(
            activity["reconciliation_debt_report_paths"], (report_path,)
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
