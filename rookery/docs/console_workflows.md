# Shared Interactive Resources

An optional extension may expose a streamed console, browser session, hardware
interface, or another shared interactive resource. That resource belongs to
one input owner at a time. Other workers analyze saved artifacts until the
owner transfers the lease.

The selected extension defines the concrete lease and evidence commands. Read
its active-surface entry and adapter-local documentation before taking input.

## Working Rule

1. Confirm the current attempt or session and its permitted actions.
2. Name one input owner and one bounded task.
3. Preserve the interaction evidence as it occurs.
4. Release or transfer ownership with the latest evidence path and state.

Prefer a terminal command, API, file export, or script over fragile click
coordinates. An evidence bundle should retain the exact action or command,
selected resource, timestamps, byte-safe exports when available, useful frames
or screenshots, checksums, and one manifest. A screenshot alone rarely proves
what happened.

Session health is read-only. A session or authentication pause can stop new
platform-heavy work while local analysis continues; it never substitutes for
the canonical `./go stop` generation barrier. See
[Platform sessions](./platform_sessions.md) and [Evidence and state](./evidence_state.md).
