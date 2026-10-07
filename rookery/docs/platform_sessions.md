# Platform And Session Capabilities

Rookery is generic. Authenticated APIs, dynamic attempts, browser sessions,
event streams, and consoles exist only when the selected adapter or extension
declares them. Read the active-surface entry and adapter-local documentation
before assuming a platform capability exists.

## Operating Rules

- Treat session health checks as read-only.
- Read the selected attempt or session state before starting or resetting a
  dynamic attempt.
- Bind evidence and proposals to current attempt or session identifiers when
  the adapter supplies them.
- Keep platform mutation in the reviewer, authorizer, and executor path.
- Continue local artifact analysis during a platform outage when the event
  scope still permits that work.
- Keep authentication or session pauses separate from operator stop.

`./go stop` is the only supported operator stop. It advances the canonical
stop generation and revokes Rookery authority. Do not create
`control/STOP_REQUESTED` as an operator control; legacy helpers may observe it,
but it does not implement the supported stop transition.

The optional `platform-heavy-pause` helper can create
`control/AUTH_PAUSED` and `control/PLATFORM_HEAVY_PAUSED` to record that new
platform-heavy lanes should wait for refreshed credentials or session health.
That pause does not stop local analysis, writeups, report harvest, or the
canonical event lifecycle. Clear it only through the helper after the relevant
adapter/session evidence is healthy.

Platform-specific commands, fields, session freshness rules, and permitted
mutations belong in adapter-local docs. The generic state and authorization
rules are in [State, policy, and stop](./state_policy_stop.md) and
[Scoring and review](./scoring_review.md).
