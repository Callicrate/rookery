# Writeup Voice Guide

Write for the next technically capable operator who needs to reproduce the
result, audit the evidence, and understand the decisions that mattered.

## Core Rules

- Lead with the result and the evidence that establishes it.
- Use short, direct prose. Prefer an exact path, command, artifact, or response
  over a vague summary.
- Explain why each material step mattered. Do not turn a command transcript
  into a story without interpretation.
- Separate observation, inference, experiment, rejected route, and accepted
  result. State uncertainty precisely.
- Preserve the path from raw artifact to scorer truth. A transport success or
  relay acknowledgement is not proof by itself.
- Include a rerunnable command or script path, required inputs, environment
  assumptions, and verification result.
- Record side effects and cleanup truthfully, including when none occurred.

## Structure

Use the generated `WRITEUP.md` headings. Fill the sections in this order:

1. **Summary:** the task, result, and decisive mechanism.
2. **Objective and context:** the scope and constraints that shaped the work.
3. **Artifacts and provenance:** exact private evidence paths and what each
   establishes.
4. **Environment:** versions, services, or setup facts needed to reproduce.
5. **Method:** the reasoning and experiments in the order that made them
   useful.
6. **Commands and reproduction:** minimal rerunnable commands or a script,
   plus expected outputs or checks.
7. **Verification and scorer truth:** accepted response or verifier evidence
   and its path.
8. **Final action or answer reference:** a reference to the private accepted
   value or action evidence.
9. **Rejected near misses and dead paths:** only routes that teach a useful
   boundary, with the evidence that rejected them.
10. **Lessons for reproduction:** challenge-specific advice for repeating the
    technical method.

## Evidence And Audience

The in-event writeup is private evidence. Preserve exact flags, candidates,
responses, sessions, commands, logs, and paths there when they are necessary
for reproducibility. Do not redact the private writeup or substitute a
remembered summary for evidence. Bounded adapter response summaries have their
own credential-sanitization contract in [Evidence and state](evidence_state.md).

If an operator later asks for a public export, write a separate derivative from
the private record. Remove secrets and protected event material, retain only
claims the public material can support, and link to public-safe artifacts rather
than private paths. Do not overwrite the private writeup to make it publishable.
