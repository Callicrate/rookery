# Network And VPN

Rookery does not manage a VPN client, daemon, profile, credential file, route,
or privileged process in this release. Establish any required private-network
connection before starting Rookery through an externally supervised operator
workflow, and stop it through that same workflow.

No functioning Rookery-managed VPN commands exist in this release. The retained
refusal shims are `bin/vpn`, `bin/vpn-status`, `bin/vpn-health`,
`bin/vpn-connect`, and `bin/vpn-reconnect`. Operational requests return
`vpn_privileged_supervision_unavailable` before they read configuration,
profiles, state, or logs. They do not report VPN health, create a connection,
signal a process, or clean up legacy VPN state.

Rookery does not treat `state/vpn` material as authority to start, stop, or
report health for an externally supervised connection. Any such state is
historical residue.

Existing local `VPN_*` values can remain in a live `.env`, but they are ignored
and are not release configuration. The shipped `.env.example` has no VPN
lifecycle settings.

The operator remains responsible for keeping all network use inside the
declared event scope. Rookery-owned network and attachment helpers enforce the
compiled scope for their own requests. Raw-shell network work is still subject
to that scope and its evidence requirements, but Rookery cannot supervise
external routing or prove ownership of an external VPN process.

See [Scope](./scope.md) for network authorization and
[Tools and wrappers](./tools_and_wrappers.md) for the currently supported
Rookery-owned network paths.
