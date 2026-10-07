# Contributing to Rookery

Rookery coordinates autonomous security work with broad local authority. Small changes can affect scope enforcement, evidence integrity, scoring mutations, or shutdown behavior, so contributions should be narrow, source-backed, and easy to verify.

## Contents

- [Before you start](#before-you-start)
- [Development environment](#development-environment)
- [Make a focused change](#make-a-focused-change)
- [Verification](#verification)
- [Documentation](#documentation)
- [Submitting a change](#submitting-a-change)

## Before you start

Read these first:

- [`README.md`](README.md) for the repository boundary;
- [`docs/architecture.md`](docs/architecture.md) for the component and trust model;
- [`AGENTS.md`](AGENTS.md) for repository guidance; and
- the nearest documentation under [`rookery/docs/`](rookery/docs/) for the behavior you plan to change.

For substantial work, coordinate through the project's current contribution channel before investing in a large implementation. Do not include credentials, event evidence, candidate answers, private telemetry, or vulnerability details in a public discussion.

## Development environment

The full runtime and its POSIX security checks require Linux or WSL. Keep an operational workspace on a Linux filesystem. Use Python 3.11 or newer for development and tests. Python-only development can work on other platforms, but that does not verify the supported launch path.

The repository has two intentional layers:

- `rookery/` is the canonical deployable source;
- the repository root contains tests, contributor documentation, maintenance skills, and strict delegating wrappers.

Shipped code must not depend on repository-only files. Do not add runtime state, event data, release archives, databases, logs, captures, telemetry, or retrospective evidence to this repository.

## Make a focused change

1. Read the implementation, its callers, adjacent documentation, and focused tests.
2. Preserve the public operator surface: `./go`, `./go status`, and `./go stop`.
3. Keep platform-specific behavior inside the selected adapter and optional activity modes inside extensions.
4. Preserve the separation between proposal, independent review, authorization, execution, and scorer verdict.
5. Update operator documentation when behavior or configuration changes.
6. Add or adjust a focused regression test when the change affects behavior or a security boundary.

Do not weaken a fail-closed path to make a test or local setup pass. If a contract needs to change, make that decision explicit in code, documentation, and tests.

## Verification

Run the smallest focused test first. Test modules use Python's standard `unittest` runner. From the repository root, the complete repository suite is:

```bash
python tests/rookery/run_acceptance.py
```

Run the release validator against a source tree without runtime residue:

```bash
cd rookery
PYTHONDONTWRITEBYTECODE=1 ./bin/rookery validate --release --source-checkout
```

The optional Ruff configuration targets Python 3.11 and checks selected
`pyflakes` and `pycodestyle` rules. If Ruff is installed in your development
environment, run:

```bash
python -m ruff check .
```

Some integration tests require Linux or WSL and will skip elsewhere. A change to launch, filesystem containment, process ownership, permissions, or effect-producing behavior needs verification on the supported POSIX runtime.

## Documentation

Keep commands and paths executable as written. State side effects next to mutating commands, distinguish source validation from event readiness, and link to the canonical contract instead of copying it into several pages.

Use the project terms consistently:

- **operator** owns event facts, scope, policy, authorization, resume, and stop;
- **worker** owns one bounded question and its assigned report;
- **reviewer** independently assesses a proposal;
- **executor** performs only an immutable, reviewed, authorized action; and
- **scorer truth** is the structured platform verdict, not transport acknowledgement.

## Submitting a change

Provide a concise description of the user-visible behavior, the trust boundary it touches, and the exact verification you ran. Call out skipped platform checks and remaining risks. Keep unrelated cleanup in a separate change so reviewers can follow the security argument.

By participating, you agree to follow the [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Report security-sensitive findings through [`SECURITY.md`](SECURITY.md), outside public review.

Unless stated otherwise, contributions are submitted for distribution under the [MIT License](LICENSE).
