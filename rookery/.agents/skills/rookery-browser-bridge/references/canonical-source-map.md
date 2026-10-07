# Canonical Rookery Sources

Paths below are relative to the installed Rookery root unless the runbook names the transferred Windows bundle.

| Source | Use |
| --- | --- |
| `docs/browser_bridge.md` | Canonical export, start, health, Stop, restart, replacement, and rollback sequence. |
| `docs/upgrade.md` | Side-by-side release upgrade and rollback boundary. |
| `docs/preparation.md` | Browser-backed adapter readiness and session recovery handoff. |
| `docs/tools_and_wrappers.md` | Browser-bundle and browser-health public command boundaries. |
| `bin/browser-bridge-bundle` | Immutable bundle exporter from a verified release archive and manifest. |
| `bin/browser-gateway-policy` | Private baseline-bound gateway-policy exporter. |
| `bin/browser-health` | Linux or WSL read-only bridge health check. |
| `bin/start-chrome-cdp.ps1` | Source form of the helper; operate only its bundle copy. |
| `adapters/<selected-id>/README.md` | Selected adapter bridge, session, and post-health sync contract. |
