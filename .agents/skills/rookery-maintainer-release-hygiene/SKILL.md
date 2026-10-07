---
name: rookery-maintainer-release-hygiene
description: "Use when asked to prepare, audit, or package a Rookery source release. Validates immutable handoff artifacts. Do not trigger for deployment, event work, browser operations, or publishing."
metadata:
  short-description: Prepare Rookery source releases.
---

# Rookery Maintainer Release Hygiene

## When to Use

- Prepare the canonical Rookery source for a release.
- Audit release documentation, source residue, and supported command surface.
- Build or verify a local immutable release handoff.

## When NOT to Use

- Configure or launch an event, operate a browser bridge, or execute a scoring action.
- Deploy an archive to a workspace or change its private `.env`.
- Publish a release, create a hosted tag, upload artifacts, or announce availability.

## Workflow

1. Locate the canonical source root. In this development workspace it is `rookery/`; source paths in this skill are relative to that directory. Run Rookery Bash commands only in Linux or WSL.
2. Read `README.md`, `docs/operator.md`, `docs/upgrade.md`, and `docs/tools_and_wrappers.md`. Keep the documented everyday surface aligned with `./go`, `./go status`, and `./go stop`.
3. Inspect the candidate tree for runtime residue, live configuration, evidence, generated state, private data, and stale documentation before packaging. Preserve evidence-bearing workspaces; do not delete or fold them into a release.
4. Verify a template-only source checkout with `PYTHONDONTWRITEBYTECODE=1 ./bin/rookery validate --release --source-checkout`. Verify an installed extraction with `PYTHONDONTWRITEBYTECODE=1 ./bin/rookery validate --release`. Resolve each issue at its source instead of masking it in the archive.
5. When the task authorizes a local artifact, use `./bin/build-release` with an empty output directory outside the source tree. Review the ZIP, structured manifest, and SHA-256 sidecar as one immutable release triplet.
6. When the handoff includes a browser bridge, verify the bundle exported by `./bin/browser-bridge-bundle` binds to that exact release archive and manifest. Check `bridge-bundle.json` before transfer; do not start, deploy, or configure the bridge here.
7. Hand off the validation result, artifact locations, documentation changes, immutable bindings, remaining approval gate, and intentionally unverified external boundary. Do not assign approval, publish, or distribute from local validation alone.

## Boundaries

- The release archive contains the reviewed `.env.example`, never a live `.env`, runtime state, or event evidence.
- Receive and upgrade releases side by side; do not overlay an evidence-bearing workspace or migrate runtime state into a new tree.
- Browser bridge operation and event configuration belong to their respective operational skills.

## Deterministic Tools

This skill ships no helper scripts. Run the canonical validator, release builder, and conditional bridge exporter from the target repository only when the current task authorizes their effects.

## References

- Read the [canonical source map](references/canonical-source-map.md) for the release contracts behind this workflow.
