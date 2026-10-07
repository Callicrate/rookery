# Solve Capsules And Writeups

Closeout has a capsule and a writeup for each verified completed objective.
Scorer-accepted solves and reviewed non-scoring evidence have different capsule
types.

## Solve Capsule

Create `writeups/<id>/CAPSULE.json` after the selected scorer accepts an
objective. Its
canonical payload records:

- objective identifier;
- action reference and scorer evidence;
- reproduction path;
- material provenance paths; and
- a dead-path checkpoint.

Use `./bin/solve-capsule` or the `writeup capsule` maintenance command with the
exact accepted plan ID as its action reference and the canonical terminal
response path as scorer evidence. Rookery checks the matching proposal,
independent review, plan, consumed authority, execution start, and accepted
scorer verdict before it writes the capsule. The capsule is content-addressed
and is not a narrative substitute for the later writeup.

A completed `no_submit_evidence` plan can create
`writeups/<id>/EVIDENCE_CAPSULE.json`. It records reviewed analysis evidence,
not a platform solve. An approved proposal, successful HTTP transport, or
free-form evidence string cannot create a solve capsule. Existing unbound
capsules remain private but are reported as unverified for closeout.

## Complete Writeup

Every verified completed lab, challenge, puzzle, hill, or task needs
`writeups/<id>/WRITEUP.md` before final closeout. Create the starter with
`./bin/writeup-new <id> --title "..."`, then write the explanation using
[Voice](./voice.md). `./bin/writeup-check --closeout` reports missing capsules,
missing required writeups, and required-section failures.

The generated writeup includes sections for summary, context, artifacts and
provenance, environment, method, commands and reproduction, verification and
scorer truth, final action reference, rejected paths, and reproduction lessons.
The validator requires at least Summary, Artifacts And Provenance, Commands And
Reproduction, and Verification And Scorer Truth.

`WRITEUP_MODE` in `.env` controls whether a full writeup is required
immediately or at closeout. The generic profile defaults to closeout. A
partial-objective report can document accepted work while other objectives
remain active, but it does not mark the whole task complete.

## Private Evidence And Public Exports

Runtime writeups are private event evidence. They may reference exact values,
commands, raw responses, sessions, and paths needed for reproduction. Do not
redact or rewrite that evidence during the event.

A public writeup is a separate, deliberate export. It must be derived from the
private record, omit secrets and protected event material, and say what it can
support without pretending that omitted evidence is public. The private
runtime remains the provenance authority. See [Evidence and state](./evidence_state.md).
