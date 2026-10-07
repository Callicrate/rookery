# Security Policy

Rookery is security tooling with intentionally broad local authority. A defect can affect operator files, event scope, credentials, evidence, scoring actions, or process control. Please report suspected vulnerabilities privately.

## Reporting a vulnerability

On GitHub, use **Security and quality → Report a vulnerability** when that
private reporting option is available. If the option is unavailable, open a
minimal issue asking for a private maintainer contact without including
technical details.

## GitHub publication setup

Before publishing Rookery on GitHub, maintainers should:

1. create the empty public GitHub repository, because
   [private vulnerability reporting](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository)
   is available for public repositories;
2. enable private vulnerability reporting in the repository's security
   settings and configure the responsible maintainers' security-alert and
   email notifications;
3. verify from a non-maintainer account that the repository's Advisories page
   offers the private report form; then
4. push the reviewed source and announce the project.

This policy does not claim that a private report form is currently configured.

Include, when safe:

- the affected version or commit;
- the operating environment;
- the violated security boundary;
- minimal reproduction steps;
- the expected and observed result; and
- whether credentials, private evidence, or a platform mutation may be involved.

Do not include live credentials, flags, candidate answers, private event evidence, or data from systems you are not authorized to test. Preserve exact evidence privately. Do not test a suspected issue against a live event or third-party platform without explicit authorization.

Maintainers should acknowledge the report through the same private channel, establish a safe reproduction boundary, and coordinate disclosure after a fix and verification plan exist. This repository does not currently publish a guaranteed response time or an authenticated security mailbox.

## Supported versions

This repository does not yet declare a supported release series. Security fixes target the current source until a release support policy is published. Historical snapshots and rejected release artifacts are not supported.

## Security model

Rookery relies on several independent boundaries:

- event scope is explicit and starts unresolved;
- scoring authorization starts at zero;
- solvers propose, independent reviewers review, and a separate executor mutates;
- Rookery-owned network helpers enforce compiled scope before access;
- stop generation is checked immediately before mutations;
- exact captured evidence is retained privately, while bounded adapter
  summaries replace sensitive authentication and cookie headers; and
- release integrity hashes do not authenticate a publisher.

The Codex process itself runs with the filesystem, process, and network authority of the operator account and with interactive approvals disabled. Arbitrary raw shell cannot be completely mediated by Rookery. Operators must use a dedicated workspace, restrict event scope, protect runtime evidence, and supervise the environment.

For more detail, read [`docs/architecture.md`](docs/architecture.md), [`rookery/docs/scope.md`](rookery/docs/scope.md), [`rookery/docs/scoring_review.md`](rookery/docs/scoring_review.md), and [`rookery/docs/state_policy_stop.md`](rookery/docs/state_policy_stop.md).
