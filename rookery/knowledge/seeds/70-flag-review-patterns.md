# Flag Review Pattern Notes

Solvers propose candidates; review submits.

Good candidate signals:

- Matches published flag regex/prefix exactly.
- Comes from a deterministic solver, exploit output, direct artifact extraction, or source-backed proof chain.
- Has verifier report and repro/proof path.
- Does not duplicate a rejected candidate.
- Fits event style after enough accepted examples exist.

Anomaly signals:

- Does not match event flag regex.
- Placeholder-looking: `flag`, `a-flag`, `test`, `example`, `password`, `admin` without exact source.
- Very different length or punctuation from many accepted examples.
- No verifier/repro path for attempt-limited challenges.
- Semantic/nearby OSINT guess with unresolved clue fragments.

Anomaly does not mean discard. It means hold for human/reviewer, preserve exact evidence, and avoid wasting attempts.
