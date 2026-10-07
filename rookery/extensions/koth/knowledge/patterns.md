# Live Target and KOTH Patterns

- Maintain a live target inventory with host, ports, source, confidence, last-seen time, scoring path, and stale/down status.
- Treat target-side handle writes as scoring actions. Solver agents propose them; independent review executes them.
- Before reversible remote changes, register cleanup: AD group modifications, tunnels, added keys/users, routing changes, service changes, background brute/scan jobs.
- For Windows KOTH file writes, exact bytes matter. Prefer ASCII/no newline, read bytes back, and save transcript.
- For Linux KOTH file writes, discover expected paths first; avoid broad filesystem writes. Verify with hex or exact file readback.
- Refresh credential validity after resets. Stale credentials should be demoted, not treated as permanent truth.
- SSH-only targets need separated hypotheses: password, key, GSSAPI/AD membership, cloud-init, machine-account, authorized_keys provenance.
- For range resets, stale dead paths become stale-failed until revalidated.
- Platform solve/score drift is a signal to refresh state, not proof of an answer.
