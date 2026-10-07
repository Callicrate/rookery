# Canonical Rookery Release Sources

Paths below are relative to the canonical Rookery source root, currently `rookery/` in this development workspace.

| Source | Use |
| --- | --- |
| `README.md` | Public operator surface, release archive shape, and packaging entry point. |
| `docs/operator.md` | Supported operator and maintenance command boundaries. |
| `docs/upgrade.md` | Approval, receiving, side-by-side upgrade, and rollback contracts. |
| `docs/tools_and_wrappers.md` | Release packaging and browser-bridge export behavior. |
| `docs/browser_bridge.md` | Conditional browser-bridge bundle binding and handoff contract. |
| `bin/rookery` | Release validation entry point. |
| `bin/build-release` | Deterministic ZIP, manifest, and sidecar builder. |
| `bin/browser-bridge-bundle` | Conditional release-bound browser bridge exporter. |
| `.env.example` | Reviewed configuration template included in a release. |
