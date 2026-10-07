---
name: rookery-event-retrospective
description: "Use when asked to review a finished Rookery event or compare preserved runtime telemetry. Uses read-only private evidence. Do not trigger for live operations, MOP history, or public writeups."
metadata:
  short-description: Review preserved Rookery event evidence.
---

# Rookery Event Retrospective

## When to Use

- Review a completed, stopped, or blocked Rookery event.
- Turn preserved runtime telemetry into evidence-backed improvements.
- Compare two eligible preserved Rookery runtimes.

## When NOT to Use

- Recover, migrate, or resume runtime state.
- Review MOP-owned AI conversation history, prompts, or account data.
- Operate an active event or publish an external report.

## Workflow

1. Identify a preserved, quiescent whole runtime directory and the matching source root. A runtime is not a selected set of `state/` files; it may contain credentials, exact evidence, and candidates. Run any Rookery Bash command only in Linux or WSL.
2. Keep the runtime private and unchanged. Do not redact, normalize, migrate, or copy raw event data into this public repository or a public retrospective.
3. Read `docs/evidence_state.md`, `docs/measurement.md`, `docs/lessons.md`, `docs/writeups.md`, and `docs/voice.md` from the canonical source root before interpreting results.
4. Before generating a report, require an explicitly supplied private output directory outside both the public source root and the preserved runtime. Without one, inspect evidence read-only and return findings without writing output.
5. Run the Rookery telemetry reporter only against the preserved runtime and write generated output in that supplied private directory. Use `--source-root` when retained evidence names a different deployed source location.
6. Treat telemetry as descriptive. Report counts with denominators, retain configuration and platform differences as confounders, and distinguish evidence gaps from successful outcomes.
7. Compare two runs only when both reports are eligible and the supplied private output directory is available. Let `bin/telemetry-compare` regenerate reports from preserved evidence; do not supply hand-authored report JSON as provenance.
8. Write an improvements-focused retrospective that separates observed facts, inferences, limitations, and proposed changes. Do not include raw candidates, secrets, command arguments, output content, MOP history, or a challenge solution unless the operator has separately authorized a private artifact.

## Boundaries

- `bin/telemetry-report` is read-only, but its inputs remain sensitive private evidence.
- No retrospective can establish improved solve rate, ideal concurrency, or causal effectiveness from a single event.
- Rookery stop lessons are future improvements only; they are not a run-status report.

## Deterministic Tools

This skill ships no helper scripts. Run the canonical Rookery reporter and comparator only in Linux or WSL, against authorized private paths, with generated output in the explicitly supplied private directory.

## References

- Read the [canonical source map](references/canonical-source-map.md) for evidence handling and reporting contracts.
