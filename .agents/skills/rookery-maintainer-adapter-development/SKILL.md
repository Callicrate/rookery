---
name: rookery-maintainer-adapter-development
description: "Use when asked to add, change, or review a Rookery platform adapter. Maintains normalized contracts and validation. Do not trigger for event setup, active-event work, or release deployment."
metadata:
  short-description: Maintain Rookery platform adapters.
---

# Rookery Maintainer Adapter Development

## When to Use

- Add a platform adapter or support a new platform capability.
- Change adapter environment, inventory, detail, attachment, preflight, or execution behavior.
- Review an adapter's normalized contract, generic-controller isolation, or validation coverage.

## When NOT to Use

- Configure a selected adapter for one event; use event preparation.
- Run an event, solve a challenge, submit an answer, or operate a browser bridge.
- Package, deploy, or approve a release; use maintainer release hygiene.

## Workflow

1. Read the selected adapter's `README.md`, `adapter.json`, `profile.json`, and `env.example`, then read the generic contracts named in the [source map](references/canonical-source-map.md). Treat the selected adapter's descriptor and typed environment schema as the boundary for adapter-owned configuration.
2. Make the smallest complete change across the descriptor, profile, environment example, documentation, implementation, and focused tests. Preserve the normalized `sync()`, `detail()`, `capture_file()`, `preflight_action()`, and `execute_action()` contracts consumed by generic controllers.
3. Keep platform-specific authentication, session refresh, scope admission, redirect handling, and transport behavior inside the adapter or its owned helper. Do not add platform conditionals to generic controllers, grant new event authority, or weaken execution, review, scope, or stop-generation checks.
4. Model inventory rows and detail results explicitly. Keep unsupported or non-submittable challenge states visible as typed row-local results. Preserve fresh detail reads, attachment provenance, canonical scorer truth, and cleanup behavior where the platform supports them.
5. Update documentation for configuration, capabilities, and known limits. Do not put a live `.env`, session material, captured evidence, or platform-specific secrets in the repository.
6. Run the canonical focused tests for the changed adapter and its generic contracts, then run the source validator from Linux or WSL: `PYTHONDONTWRITEBYTECODE=1 ./bin/rookery validate --release --source-checkout`. If release metadata changes, use maintainer release hygiene after this workflow.

## Deterministic Tools

This skill ships no helper scripts. Use the repository's canonical validator and focused test suite; do not create a parallel adapter validator.

## References

- Read the [canonical source map](references/canonical-source-map.md) before changing adapter contracts.
