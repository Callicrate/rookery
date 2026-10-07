# Event Scope

Rookery-owned network and attachment operations start closed. The operator declares the boundary with `ALLOWED_HOSTS`, `ALLOWED_CIDRS`, `ALLOWED_PORTS`, `ALLOWED_PROTOCOLS`, `ALLOWED_FILE_ORIGINS`, `PLATFORM_HOSTS`, `SCOPE_MAX_BYTES`, and `SCOPE_EXPIRES_AT` in `.env`, then sets `EVENT_SCOPE_ACK=1` only after review. Rookery assigns the compiled scope generation from canonical runtime state. A missing acknowledgement, empty usable boundary, invalid limit, or expired scope blocks the affected operation before I/O.

Scope is event configuration. Edit only the private `.env`; do not edit `state/scope.json`, which is a checked generated cache of the compiled result. See [Event configuration](./event_profiles.md).

## What each declaration authorizes

| Field | Meaning |
| --- | --- |
| `allowed_hosts` | General target host patterns. Names are canonicalized with ASCII IDNA and trailing-dot normalization before matching. |
| `platform_hosts` | Control-plane host patterns used only for platform-tagged access. Keep them distinct from challenge targets. |
| `allowed_cidrs` | Numeric-address authority. Literal IP targets require a matching CIDR; special or non-global DNS answers do too. |
| `allowed_ports`, `allowed_protocols` | Exact network ports and protocol names allowed for a checked effect when the list is nonempty. An empty list leaves that dimension unrestricted after the host/CIDR boundary passes. |
| `allowed_file_origins` | Local paths or declared attachment origins permitted for ingestion. |
| `max_attachment_bytes` | Positive upper bound for an admitted attachment. |
| `expires_at`, `acknowledged` | The time boundary and explicit approval that make the declaration active. |

Host patterns are case-insensitive shell-style patterns: `*` can span dots, `?` matches one character, and bracket expressions match listed characters. A host entry with no pattern characters is exact. Host-pattern and CIDR authority are deliberately separate: a public DNS answer can be permitted by its host pattern, while a special address needs explicit numeric authority.

## Checked transport

For an HTTP(S) effect, the scope boundary:

1. Canonicalizes and checks the URL's host, port, protocol, and platform classification.
2. Resolves the hostname once and rejects an empty set or any set containing an unauthorized answer.
3. Connects only to one of the reviewed numeric addresses.
4. Keeps the canonical hostname for the HTTP `Host` header and HTTPS SNI and certificate validation.
5. Repeats the same checks for every redirect.

This prevents a later DNS answer from changing the destination of an admitted connection. A certificate valid only for the numeric peer is insufficient for an HTTPS hostname request. URL zone identifiers are unsupported.

Scoped effects do not consume ambient proxy or CA settings. A declared proxy is refused unless a validated exact `NO_PROXY` rule selects the direct, DNS-pinned route; CIDRs, paths, schemes, userinfo, and malformed `NO_PROXY` entries are rejected. The implementation is the [scope compiler and checker](../lib/rookery/portable/scope.py) and [pinned transport](../lib/rookery/portable/scoped_transport.py).

## Compiled authority and overrides

`state/scope.json` has schema 2 and is useful for inspection. A standalone or out-of-process scoped consumer loads it through `load_canonical_compiled_scope(root)`. That check compares the stored scope with fresh resolution of the bounded current inputs and the canonical resolved manifest, confirms scope and stop generations from one SQLite snapshot under the mutation lock, and verifies the current launch binding. The in-process adapter path receives the launch-bound compiled scope from its controller. A child-producing operation rechecks that binding immediately before handoff; it does not hold the lock for the child's lifetime.

An override must state a reason and expiry and is retained as an event. Only an active, matching override can add its declared hosts or CIDRs. The current override parser accepts any syntactically valid host pattern or CIDR, including broad values; reason and expiry are required, but narrowness is an operator decision rather than an enforced rule. Stale, malformed, and oversized access still fails before a network or evidence effect.

## Boundary of enforcement

The controls above govern Rookery-owned transports, attachments, and child handoffs. They cannot intercept arbitrary commands an operator or agent runs directly in a shell. Those actions still remain inside the operator-declared event boundary and must preserve appropriate evidence. See [Evidence and state](./evidence_state.md) for what Rookery records when it does own an effect.
