# Tools And Wrappers

Rookery tools preserve evidence and enforce the boundaries that Rookery owns.
They do not replace the local shell. `ACTIVE_SURFACE.md` is the current list of
tools and agents selected for the resolved event; an adapter or extension
contributes commands only when it is enabled.

## Public And Maintenance Surfaces

Normal event control stays small:

```bash
./go
./go status
./go stop
```

Internal helpers support scope checks, normalized adapter work, frontier
ranking, proposals, review, immutable execution, queueing, evidence
reconciliation, writeups, and validation. They are coordinator-, reviewer-, or
adapter-facing rather than additional everyday controls.

Foreground challenge coordination uses native subagents in the one Codex
session. The main coordinator asks the operator how many challenges to keep
active, assigns distinct solver-ready challenges to depth-1 coordinators, and
refills slots only after reports and attempts are closed. Challenge
coordinators may delegate bounded depth-2 workers. This flow does not add an
operator command or grant scoring or platform mutation authority.

The coordinator-facing `./bin/rookery compute` commands manage a distinct
low-priority idea queue:

- `compute enqueue` records bounded, checkpointable agent or job work with a
  report path, stop condition, mechanism, resource request, budget, and dedupe
  key.
- `compute tick` samples affinity-visible Linux CPU and returns at most one
  lease or cooperative pause request. It never launches or signals a process.
- `compute start` binds a current lease to one matching registered agent
  attempt or Rookery-owned background job. A job lease supplies the exact
  `runbg` label that must identify that job.
- `compute outcome` records completion, failure, retirement, cancellation, or
  a checkpointed pause. Every outcome must repeat the admission ID and exact
  runner binding from `compute start`; duplicate terminal outcomes fail.
- `compute requeue` resumes a paused idea only after revalidating its existing
  private, regular, single-link checkpoint inside the workspace.
- `compute list` and `compute status` inspect the queue.

See [Coordination](./coordination.md) for the full lifecycle and default CPU
thresholds. The older `compute --jobs <file>` advisory scheduler remains for
compatibility.

## Evidence And Process Boundaries

`runq` runs a command with bounded capture and records a command envelope.
`run-ledger` blocks a repeated normalized reconnaissance command unless an
explicit justified recheck uses `--force`. `ncq` is the scope-authorized TCP
probe: it admits one `tcp://` target, pins the authorized DNS result, and runs
the probe without a shell. `range-sweep` accepts only a scope-granted CIDR,
TCP, and exact ports; it does not pass arbitrary scanner flags through.

Workers use `./bin/score-propose` to surface scoring candidates. Reviewers,
authorizers, and executors perform the later stages. See
[Scoring and review](./scoring_review.md).

Children receive a minimal environment and only purpose-declared keys. Codex
does not receive adapter, session, VPN, agent-socket, or owner credentials.
Exact runtime evidence stays private; [Evidence and state](./evidence_state.md)
defines retention and post-event reporting.

## Available And Unavailable Network Paths

Selected adapters provide scope-mediated inventory, attachment, and mutation
paths. SearXNG may be prepared as a research capability. Its availability is
recorded in `PREPARATION.md`. That generated file is authoritative for optional
analysis tools in the current workspace; a registry entry or documentation
example does not prove that its external dependency is installed.

`playq` is disabled because browser redirects, subresources, scripts,
WebSockets, DNS changes, and downloads are not fully scope-mediated. `webq`
is unavailable because its HTTP transport cannot enforce scope across the
complete request path. Both retain only informational help/version behavior.

`bin/browser-bridge-bundle` exports the Windows browser components from a
verified release archive and manifest into a new immutable directory. Its
bundle manifest binds the Chrome helper and sealed gateway hashes to the
release. Start, health, and guarded stop run from that bundle; a mutable source
checkout is not an operational browser bridge. The start mode resolves the
current WSL address when given a distribution and user, starts or verifies one
visible dedicated Chrome profile, creates the sealed gateway when selected,
and opens loopback-only reverse forwards for CDP and gateway status. The helper
itself does not navigate, capture, or submit.

`bin/browser-health` is the Linux/WSL read-only counterpart. It verifies the
baseline's configuration digest, the policy's binding to that digest, a bounded
Chrome CDP response, and the gateway status policy digest. It does not create
runtime state, authenticate, repair a process, or perform a platform mutation.
The canonical command sequence and restart drill are in [Browser bridge](browser_bridge.md).

The `ctfd_browser_gateway` adapter treats token and browser gateway as internal
transports under one selected adapter ID. It tries fixed read-only token requests
first and selects Chrome only for a typed token access or route-availability
failure. This transport choice does not grant scoring authority. After the
reviewed token POST call begins, the adapter never sends a second POST through
Chrome, regardless of the response or transport failure.

The public `skillbit` adapter uses the dedicated Chrome and sealed gateway as
its internal authenticated UI transport. Its exact-origin flow may establish or
refresh the configured account session, prove one configured event card,
normalize row-local challenge modalities, read rich bounded detail, authenticate
an exact attachment request from an anchor marked `mctf-s3dl`, and release one independently reviewed
scoring attempt. Attachment capture still passes through `platform ingest`, the
compiled file-origin declaration, redirect checks, byte bounds, and private
no-clobber publication. Platform and support origins are control-plane scope in
`PLATFORM_HOSTS`; they are not challenge targets. After `./go stop`, use the
bundle's guarded stop and health modes to end and verify the bridge.

`bin/browser-gateway-policy` exports the selected adapter's private,
baseline-bound gateway policy after `.env` validation and baseline verification.
Write it to a new absolute path outside the source and release, transfer its
exact bytes privately to the workstation, and pass the Windows-local path to
the Chrome helper. See [Preparation](./preparation.md) and [Platform
adapters](./adapters.md).

Other external browser or raw HTTP work is operator-side research and requires
the declared event scope; it is outside Rookery-owned evidence.

Rookery also does not manage VPN operations. Establish any required VPN through
an externally supervised workflow before launch. See [Network and VPN](./network_vpn.md).

## Compatibility Entrypoints

Some retained `bin/` executables exist for compatibility but are absent from
the active surface when no current capability route exists. In particular,
VPN lifecycle requests refuse before reading configuration or state, and
unsupported operator-stop flags refuse and direct the operator to `./go stop`.
Treat a compatibility entrypoint as unavailable unless it appears in
`ACTIVE_SURFACE.md` or its adapter-local documentation declares it.
