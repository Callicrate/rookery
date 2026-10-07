# Browser Bridge

The browser bridge is the release-bound Windows side of a browser-backed
Rookery adapter. It owns one dedicated Chrome profile, an optional sealed
gateway, and reverse SSH forwards that expose CDP and gateway status only on
the Linux or WSL loopback interface. Operate it from an exported immutable
bundle rather than a mutable source checkout.

## Execution planes

- Run release validation, baseline and policy export, bundle export, and
  `bin/browser-health` inside the installed Linux or WSL release.
- Run `bin/start-chrome-cdp.ps1` from the transferred bundle in Windows
  PowerShell.
- Keep the release, baseline, gateway policy, bridge bundle, Chrome profile,
  and ownership record as one versioned tuple.

The bridge does not start `./go`, authenticate to SkillBit, or submit an
answer. The adapter's production `sync()` owns session establishment and its
reviewed execution path owns scoring.

## Prerequisites

Before exporting the bridge:

1. Verify and extract the release on the Linux filesystem.
2. Configure its private `.env`, run strict release validation, and create its
   private measurement baseline.
3. Export a new gateway policy from that installed release.
4. Confirm Windows can start Chrome and can reach WSL SSH with key-based batch
   authentication and a previously verified host key.

Create every output path new. Do not overwrite a bundle, policy, baseline,
profile, or ownership record from another tuple.

## Export

From the installed release, export a bundle using the verified release archive
and manifest:

```bash
./bin/browser-bridge-bundle \
  --archive "$HOME/rookery-received/$VERSION/rookery-$VERSION.zip" \
  --manifest "$HOME/rookery-received/$VERSION/rookery-$VERSION.manifest.json" \
  --output "$HOME/rookery-private/browser-bridge-$VERSION"
```

The no-clobber output contains `bin/start-chrome-cdp.ps1`,
`bin/browser-scope-gateway.py`, the required portable library, and
`bridge-bundle.json`. The manifest binds the included file hashes, source tree,
release archive, and release manifest to the named release. Transfer the exact
bundle directory and private gateway policy to new private Windows paths.

## Start

Use the WSL distribution and user form so the helper resolves the current WSL
IPv4 address immediately before it creates the tunnel:

```powershell
$Version = '<release-version>'
$Bridge = "$env:LOCALAPPDATA\Rookery\releases\$Version-browser-bridge"
$Policy = "$env:LOCALAPPDATA\Rookery\private\browser-gateway-policy-$Version.json"
$Profile = "$env:LOCALAPPDATA\Rookery\chrome-event-$Version"
$Identity = "$env:LOCALAPPDATA\Rookery\ssh\skillbit-wsl-ed25519"

& "$Bridge\bin\start-chrome-cdp.ps1" `
  -Mode Start `
  -WslDistribution Ubuntu `
  -WslUser user `
  -SshPort 2222 `
  -IdentityFile $Identity `
  -Port 9011 `
  -GatewayPolicyPath $Policy `
  -GatewayProxyPort 9002 `
  -GatewayStatusPort 9003 `
  -UserDataDir $Profile
```

For a non-WSL Linux host, use one explicit `-SshTarget` in place of
`-WslDistribution` and `-WslUser`. The helper verifies its sibling bundle
files before starting anything. Start refuses a conflicting or partial live
ownership record. Success returns bounded JSON containing the ownership record
and process identities needed for guarded health and teardown.

## Health

Windows health is pure read. Run it from the same bundle and identify the same
profile and policy tuple:

```powershell
& "$Bridge\bin\start-chrome-cdp.ps1" `
  -Mode Health `
  -Port 9011 `
  -GatewayPolicyPath $Policy `
  -GatewayProxyPort 9002 `
  -GatewayStatusPort 9003 `
  -UserDataDir $Profile
```

It verifies bundle hashes, the ownership record, exact process identities,
the dedicated profile and policy binding, local CDP, and local gateway status.
The recorded SSH process remains bound to the remote endpoint that the start
operation proved. Health does not create or repair a process.

From the installed WSL release, check the corresponding baseline and gateway
binding:

```bash
./bin/browser-health \
  --baseline "$HOME/rookery-baselines/<version>-threatcon1-skillbit-9011.json" \
  --policy "$HOME/rookery-private/skillbit-browser-gateway-policy-<version>-9011.json" \
  --cdp-url http://127.0.0.1:9011 \
  --gateway-status-url http://127.0.0.1:9003 \
  --bridge-metadata /mnt/c/Users/<user>/AppData/Local/Rookery/releases/<version>-browser-bridge/bridge-bundle.json
```

This command validates the baseline configuration digest, the policy's binding
to that digest, the bridge release version and archive/manifest hashes, bounded
Chrome CDP readiness, and the policy digest reported by gateway status. It
creates no state, does not authenticate, and does not repair the bridge. Both
health commands must pass before the adapter's read-only production `sync()`
check.

## Stop

After `./go stop`, or before replacing a bridge tuple, stop only the processes
owned by the record:

```powershell
& "$Bridge\bin\start-chrome-cdp.ps1" `
  -Mode Stop `
  -Port 9011 `
  -GatewayPolicyPath $Policy `
  -GatewayProxyPort 9002 `
  -GatewayStatusPort 9003 `
  -UserDataDir $Profile
```

Stop validates PID, process start time, Chrome profile arguments, gateway
policy, and bundle binding before it terminates the tunnel, gateway, and Chrome.
It then removes the ownership record. A mismatch is a stop condition; do not
kill a coincident PID. After successful stop, `-Mode Health` must report that no
regular ownership record exists for the profile; confirm the former bridge
ports have no unexpected listener before starting another tuple.

## Side-by-side upgrade

Build and verify the new release while the old tuple remains intact. Create:

- a new installed workspace and `.env`;
- a new measurement baseline;
- a new gateway policy;
- a new exported bridge bundle; and
- a new Chrome profile path.

When old and new bridges overlap, assign the new tuple distinct CDP, gateway
proxy, and gateway status ports with `-Port`, `-GatewayProxyPort`, and
`-GatewayStatusPort`. Health and guarded stop read those ports from the
ownership record; explicitly supplied values must match it.

Start the new bridge from its new bundle and distinct port tuple, then run
Windows health, WSL health, and the adapter's read-only production `sync()`.
Do not operate both Rookery workspaces against the same event concurrently.
After selecting the new tuple, stop the old bridge through its old bundle and
ownership record. Preserve the old workspace, bundle, policy, profile, and
ownership evidence until the new tuple is accepted. Rollback stops the new
tuple and selects the complete old tuple; it does not mix an old profile with
a new policy or copy runtime state between workspaces.

## Restart drill

Run this drill before the event:

1. Run Windows health, WSL `browser-health`, and a production SkillBit `sync()`.
2. Use guarded `-Mode Stop` and confirm the owned listeners are absent.
3. Restart WSL and bring its SSH service back with the same restricted key.
4. Run `-Mode Start -WslDistribution ... -WslUser ...`; the helper must resolve
   the new WSL address rather than reuse the old one.
5. Repeat Windows health, WSL health, and production `sync()`.
6. Confirm that no proposal, authorization, submission, or scorer evidence was
   created by the drill.

A bundle hash, ownership, profile-policy, policy expiry, endpoint, or boot
identity mismatch fails the drill. Repair the tuple and repeat the full drill
before relying on the bridge for an event.
