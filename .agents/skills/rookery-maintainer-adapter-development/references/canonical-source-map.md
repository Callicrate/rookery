# Canonical Rookery Adapter Sources

Paths below are relative to the canonical Rookery source root, currently `rookery/` in this development workspace.

| Source | Use |
| --- | --- |
| `docs/adapters.md` | Adapter discovery, normalization, and platform-isolation contract. |
| `adapters/<id>/adapter.json` | Adapter descriptor, implementation, profile, environment schema, and local catalogs. |
| `adapters/<id>/profile.json` | Selected adapter defaults and declared capability profile. |
| `adapters/<id>/env.example` | Reviewed selected-adapter configuration example. |
| `adapters/<id>/README.md` | Adapter-specific setup, capability, and limitation contract. |
| `adapters/<id>/adapter.py` | Platform implementation of normalized reads and reviewed execution. |
| `lib/rookery/portable/adapters.py` | Generic adapter interface and loader. |
| `lib/rookery/portable/event_env.py` | Typed selected-adapter environment resolution and isolation. |
| `lib/rookery/portable/environment.py` | Resolved environment and launch configuration contracts. |
| `lib/rookery/portable/cli.py` | Generic inventory, intake, capture, and command dispatch. |
| `lib/rookery/portable/execution.py` | Generic proposal, review, authorization, preflight, and execution boundary. |
| `../tests/rookery/test_*adapter*.py` | Repository-level adapter and generic-contract regression coverage. |
| `bin/rookery` | Canonical strict source and installed-release validator. |
