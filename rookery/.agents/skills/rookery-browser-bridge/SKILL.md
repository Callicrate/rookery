---
name: rookery-browser-bridge
description: "Use when asked to export, start, health-check, stop, restart, replace, or roll back Rookery's Windows browser bridge. Do not trigger for event setup, solving, scoring, or raw browser control."
metadata:
  short-description: Operate the Rookery browser bridge.
---

# Rookery Browser Bridge

## When to Use

- Export or transfer a release-bound Windows browser bridge.
- Start, health-check, stop, or restart the bridge from its immutable bundle.
- Replace a bridge during an upgrade or select the old complete tuple for rollback.

## When NOT to Use

- Configure an event, baseline, scope, or selected-adapter account; use `rookery-event-preparation`.
- Solve challenges, review candidates, grant submission authority, or submit an answer.
- Navigate or control Chrome outside the documented helper.

## Workflow

1. Work from the installed Rookery root on Linux or WSL and read the [canonical source map](references/canonical-source-map.md). Treat the release, baseline, gateway policy, immutable Windows bundle, dedicated Chrome profile, and ownership record as one versioned tuple. Do not mix members from different tuples.
2. Before export, verify the installed release, its private `.env`, and the release-bound baseline. Export the private gateway policy from that installed release, then use `./bin/browser-bridge-bundle` with the verified release archive and manifest to create a new no-clobber bundle. Transfer the exact bundle and policy to new private Windows paths.
3. From Windows PowerShell, run the bundle's `bin/start-chrome-cdp.ps1 -Mode Start`. Use `-WslDistribution` and `-WslUser` for WSL so the helper resolves the current address, or one explicit `-SshTarget` for a Linux host. Supply the matching private policy, dedicated profile, SSH identity, and CDP port. Start refuses a conflicting or partial ownership record.
4. Verify Windows health from the same bundle with `-Mode Health` and the exact policy, profile, and port. Then run the installed release's `./bin/browser-health` with the matching baseline, policy, CDP URL, gateway-status URL, and transferred `bridge-bundle.json`. Both checks are pure reads and must pass before handing the bridge to adapter session preparation.
5. For a restart drill, first run both health checks, stop with the guarded helper, confirm ownership and listeners are gone, restart the WSL SSH side if required, start again using WSL discovery, and repeat both health checks. Do not create proposals, authority, submissions, or scorer evidence during the drill.
6. For replacement, build a complete new tuple while preserving the old tuple. Stop the old bridge through its old bundle and ownership record, start the new tuple, run both health checks, and hand off to event preparation for the selected adapter's session check. Preserve the old tuple until the new one is accepted.
7. For rollback, stop the new bridge through its matching bundle, select the entire retained old tuple, run both health checks, and hand off to event preparation. Do not copy runtime state or reuse a profile with a different policy.

## Boundaries

- Start, health, and guarded Stop run from the immutable transferred bundle, never from a mutable checkout.
- The bridge does not start `./go`, authenticate a platform account, configure an event, or submit an answer.
- `./go stop` does not stop workstation-side bridge processes. Use the bundle's guarded Stop mode and its ownership record.
- A health failure is a tuple repair or replacement problem; do not kill an unverified PID or bypass a mismatched policy, bundle, or profile.

## Deterministic Tools

This skill ships no helper scripts. Use the installed release's `bin/browser-bridge-bundle` and `bin/browser-health`, then the transferred bundle's `bin/start-chrome-cdp.ps1` as documented in the browser bridge runbook.

## References

- Read the [canonical source map](references/canonical-source-map.md) for exact command forms and tuple contracts.
