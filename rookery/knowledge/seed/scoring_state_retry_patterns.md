# Canonical scoring state and scheduled retry patterns

- Treat HTTP 200 and wrapper success as transport only. Scorer fields decide accepted/rejected.
- Use one normalized scoring event stream for review, frontier, writeups, and ledgers.
- Collapse stale proposal labels under later platform accepted/rejected events.
- If evidence is time-gated, schedule a retry with earliest time, trigger, previous negative snapshot, and commands.
- A due retry gets one bounded fresh check. If no signal changed, write a new negative snapshot and stop.
- Newly visible challenges should be ingested with full detail, authorized files, hashes, and classification before assignment.
- Policy-blocked/operator-only restrictions are authorization boundaries, not stuck labels.
- Near-miss retries must test entity/field assumptions, not only spelling and casing.
