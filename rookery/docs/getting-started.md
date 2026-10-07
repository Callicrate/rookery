# Getting Started

This path starts with a source checkout the operator already trusts, builds the release locally, installs it into a new WSL/Linux directory, and stops just before the first consequential launch.

## Contents

- [Target environment](#target-environment)
- [1. Establish source trust](#1-establish-source-trust)
- [2. Run read-only checks](#2-run-read-only-checks)
- [3. Build the release](#3-build-the-release)
- [4. Verify and extract](#4-verify-and-extract)
- [5. Configure the event](#5-configure-the-event)
- [6. Create the measurement baseline](#6-create-the-measurement-baseline)
- [7. Prepare a browser session when required](#7-prepare-a-browser-session-when-required)
- [8. Review autonomous access](#8-review-autonomous-access)
- [9. Start and stop](#9-start-and-stop)
- [Expected results and common failures](#expected-results-and-common-failures)

## Target environment

Run the commands in a Linux shell. Ubuntu on WSL 2 is the primary first-run environment. Keep build artifacts, the extracted workspace, the baseline, and runtime state under the Linux home filesystem, such as `$HOME/rookery-builds` and `$HOME/rookery-installs`.

Rookery requires Bash, Python 3.11 or newer, and the Codex CLI with a working login. The preflight below checks the installed Python version before it invokes any Rookery command.

A trusted source checkout or received artifact set can be read from another mounted filesystem for validation or transfer. Do not use a Windows-mounted path such as `/mnt/c/...` for the evidence-bearing runtime. Native Windows can inspect portable source, but runtime preparation and mutation require Linux or WSL.

## 1. Establish source trust

Obtain the checkout through a channel you choose and trust. Verify its identity using that channel's own controls before running repository code. This project does not name a canonical remote, ship a publisher signature, or define a hosted support channel.

The public repository keeps its deployable release source in the `rookery/` directory. Repository-only tests, contributor files, and maintenance skills remain outside that release boundary.

A release ZIP, its SHA-256 sidecar, and its manifest can prove that local files match one another. If an attacker can replace all three, those hashes do not identify the publisher.

Set the trusted source path after you have made that decision:

```bash
PUBLIC_CHECKOUT="$HOME/src/rookery"
TRUSTED_SOURCE="$PUBLIC_CHECKOUT/rookery"
cd "$TRUSTED_SOURCE"
```

## 2. Run read-only checks

Confirm the commands needed to validate, build, receive, and launch:

```bash
for command in bash python3 sha256sum codex; do
  command -v "$command" >/dev/null || {
    printf 'missing required command: %s\n' "$command" >&2
    exit 2
  }
done
python3 -I -S -B -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else "Rookery requires Python 3.11 or newer; found " + sys.version.split()[0])'
codex login status
PYTHONDONTWRITEBYTECODE=1 ./bin/rookery validate --release --source-checkout
```

The source-checkout validator prints JSON with `"ok": true` on success. It requires the reviewed `.env.example` while allowing the live `.env` to be absent. It rejects runtime residue, missing release files, undeclared top-level paths, invalid integration descriptors, and unsafe release configuration.

A clean source checkout may omit live `.env`. The reviewed `.env.example` is mandatory. Do not create live configuration in the source checkout just to build a release.

Inventory the commands declared as required event capabilities without changing the host:

```bash
for command in curl git jq rg file strings objdump readelf xxd tar gzip unzip; do
  command -v "$command" >/dev/null || printf 'missing event capability: %s\n' "$command" >&2
done
```

Install a missing capability from a trusted offline source before launch, or deliberately enable bounded network preparation later with `ROOKERY_ALLOW_INSTALL_NETWORK=1`. The default is `0`, so Rookery does not silently download packages or images.

## 3. Build the release

```bash
VERSION="$(<VERSION)"
BUILD_DIR="$HOME/rookery-builds/$VERSION"
mkdir -p "$BUILD_DIR"
test ! -e "$BUILD_DIR/rookery-$VERSION.zip"
test ! -e "$BUILD_DIR/rookery-$VERSION.zip.sha256"
test ! -e "$BUILD_DIR/rookery-$VERSION.manifest.json"
PYTHONDONTWRITEBYTECODE=1 ./bin/build-release --output-dir "$BUILD_DIR"
```

The command prints JSON with `"ok": true` and the three artifact names. The builder always synthesizes `.env` from `.env.example`; local live values never enter the ZIP, manifest, or build summary.

## 4. Verify and extract

Use the receiver from the trusted checkout. The extraction directory must not exist:

```bash
cd "$BUILD_DIR"
sha256sum --check "rookery-$VERSION.zip.sha256"

INSTALL_DIR="$HOME/rookery-installs/$VERSION"
mkdir -p "$(dirname "$INSTALL_DIR")"
test ! -e "$INSTALL_DIR"
PYTHONDONTWRITEBYTECODE=1 "$TRUSTED_SOURCE/bin/build-release" \
  --extract-archive "$BUILD_DIR/rookery-$VERSION.zip" \
  --manifest "$BUILD_DIR/rookery-$VERSION.manifest.json" \
  --extract-dir "$INSTALL_DIR"

cd "$INSTALL_DIR/rookery"
test "$(<VERSION)" = "$VERSION"
```

The receiver verifies archive structure, bounded sizes, paths, types, modes, compression, and per-file hashes before publishing the new directory. Any mismatch is a stop condition. The synthesized `.env` is still a blank event template, so run installed-release validation after configuring it in the next step.

## 5. Configure the event

The extraction contains one editable `.env` synthesized from the reviewed example. Keep it private and open it in a trusted editor:

```bash
chmod 600 .env
"${EDITOR:?set EDITOR to your trusted editor}" .env
```

Set `EVENT_ID`, `EVENT_NAME`, the applicable event URL and times, `PLATFORM_ADAPTER`, the `ALLOWED_*` and `PLATFORM_HOSTS` scope keys, `SCOPE_MAX_BYTES`, `SCOPE_EXPIRES_AT`, `FLAG_REGEX`, `ANSWER_EXAMPLES_JSON`, and the scoring keys. Set `EVENT_SCOPE_ACK=1` only after reviewing the final scope. The root `.env.example` is the full key catalog; the selected adapter's README and `env.example` explain its subset.

For a browser-session adapter, set every required private identity, session, and anti-forgery field documented in its local README. Finalize those bindings before the baseline; Rookery does not infer them from the browser session.

When that README declares a sealed browser gateway, also set `BROWSER_GATEWAY_URL` before the baseline. Declare support origins in `ADAPTER_CONFIG_BROWSER_SUPPORT_ORIGINS` and authorize each origin's host in `PLATFORM_HOSTS`; support origins permit browser prerequisites only and never become scoring targets.

Leave `CONCURRENCY_MAX_WORKERS=auto` to use the logical CPUs available through the process's current affinity, or set a positive integer to impose a lower cap. Auto sizing does not translate a cgroup CPU quota into a lower worker count. Finalize the host size, affinity, and any explicit cap before continuing. The resolved count is recorded in the baseline, so changing it later requires a fresh baseline.

Validate the completed resolved configuration before creating its baseline:

```bash
PYTHONDONTWRITEBYTECODE=1 ./bin/rookery validate --release
```

See [Configuration](configuration.md) for the settings and trust boundaries.

## 6. Create the measurement baseline

Choose a private path outside the Rookery workspace. Put that exact absolute path in `.env` as `ROOKERY_MEASUREMENT_BASELINE_PATH`, then run:

```bash
BASELINE_DIR="$HOME/rookery-baselines"
BASELINE_PATH="$BASELINE_DIR/$VERSION.json"
mkdir -p "$BASELINE_DIR"
chmod 700 "$BASELINE_DIR"
test ! -e "$BASELINE_PATH"
grep -Fx "ROOKERY_MEASUREMENT_BASELINE_PATH=$BASELINE_PATH" .env
./bin/measurement-baseline \
  --archive "$BUILD_DIR/rookery-$VERSION.zip" \
  --manifest "$BUILD_DIR/rookery-$VERSION.manifest.json" \
  --output "$BASELINE_PATH" \
  --provider-field queue=unavailable:not_configured \
  --provider-field tokens=unavailable:not_configured \
  --provider-field usage=unavailable:not_configured
```

Success returns JSON with `"ok": true`. Replace those three provider declarations only when the selected provider supplies the corresponding post-event fields. The baseline is no-clobber and binds the release, extraction, live configuration hashes, resolved event and declared scope, resolved worker count, queue settings, and declared measurement availability without serializing environment values. The first launch records the actual stop, policy, and compiled-scope generations in `measurement.started`.

## 7. Prepare a browser session when required

Skip this step unless the selected adapter requires a browser. Use a trusted
single-user host, or provide authenticated per-user isolation. Loopback browser
control ports have no protocol authentication and can be reached by other local
accounts on that host.

For `ctfd_browser` with Firefox, start a dedicated Firefox profile with
`--remote-debugging-port <port>`, authenticate the CTFd account in that profile,
and leave exactly one page at the configured CTFd origin. Keep that Firefox
instance running and set:

```dotenv
BROWSER_MODE=bidi
BROWSER_BIDI_URL=ws://127.0.0.1:9223/session
```

Rookery checks the Firefox BiDi endpoint before launch and reads the selected
page's user agent and cookie partition during adapter preflight. It does not
perform login or navigate the page. A headless Firefox service needs an
operator-prepared authenticated profile. Do not open that profile in another
Firefox process while the service holds it. The Chrome bridge steps below
apply to `BROWSER_MODE=cdp`.

Export an immutable bridge bundle from the installed release and its verified
artifact pair. Create the output path new:

```bash
BRIDGE_EXPORT="$HOME/rookery-private/browser-bridge-$VERSION"
test ! -e "$BRIDGE_EXPORT"
./bin/browser-bridge-bundle \
  --archive "$BUILD_DIR/rookery-$VERSION.zip" \
  --manifest "$BUILD_DIR/rookery-$VERSION.manifest.json" \
  --output "$BRIDGE_EXPORT"
```

When the selected adapter requires a sealed gateway, first export its one-time policy from the installed Linux Rookery root after the baseline:

```bash
PRIVATE_GATEWAY_DIR="$HOME/rookery-private"
GATEWAY_POLICY="$PRIVATE_GATEWAY_DIR/browser-gateway-policy.json"
mkdir -p "$PRIVATE_GATEWAY_DIR"
chmod 700 "$PRIVATE_GATEWAY_DIR"
test ! -e "$GATEWAY_POLICY"
./bin/browser-gateway-policy \
  --origin 'https://platform.example' \
  --output "$GATEWAY_POLICY"
```

Keep the policy outside the source, release tree, `.env`, logs, and shared
paths. Transfer the exact bundle directory and, when required, the exact policy
bytes through the operator's authenticated private-file channel to new absolute
private Windows paths. Run the helper from that transferred bundle:

```powershell
$Version = '<release-version>'
$Bridge = "C:\RookeryPrivate\browser-bridge-$Version"
$Profile = "C:\RookeryPrivate\chrome-event-$Version"
$Identity = "C:\RookeryPrivate\ssh\rookery-ed25519"
$Policy = "C:\RookeryPrivate\browser-gateway-policy-$Version.json"

& "$Bridge\bin\start-chrome-cdp.ps1" `
  -Mode Start `
  -SshTarget 'operator@node.example' `
  -IdentityFile $Identity `
  -Port 9001 `
  -GatewayPolicyPath $Policy `
  -GatewayProxyPort 9002 `
  -GatewayStatusPort 9003 `
  -UserDataDir $Profile

& "$Bridge\bin\start-chrome-cdp.ps1" `
  -Mode Health `
  -Port 9001 `
  -GatewayPolicyPath $Policy `
  -GatewayProxyPort 9002 `
  -GatewayStatusPort 9003 `
  -UserDataDir $Profile
```

For a CDP-only bridge, omit `-GatewayPolicyPath`. For WSL, prefer the
`-WslDistribution` and `-WslUser` form documented in
[Browser bridge](browser_bridge.md) so the helper resolves the current WSL
address. Start returns bounded ownership and process identity JSON only after
its checks pass. Health verifies the same bundle, policy, profile, processes,
and endpoints without repairing them. Authenticate through the dedicated
profile and open the exact page arrangement required by the selected adapter's
local README. Keep the owned processes running. On the Linux Rookery host,
confirm `.env` contains the applicable settings:

```dotenv
BROWSER_MODE=cdp
BROWSER_CDP_URL=http://127.0.0.1:9001
# Required only by a selected sealed-gateway adapter:
BROWSER_GATEWAY_URL=http://127.0.0.1:9003
```

The launch gate verifies every required endpoint and sealed policy identity
before it creates state. Readiness does not navigate Chrome or authorize a
platform action. Use the complete [Browser bridge](browser_bridge.md) runbook
for WSL discovery, Linux `browser-health`, guarded Stop, restart, replacement,
and rollback. See [Preparation](preparation.md) for adapter readiness and
failure behavior.

## 8. Review autonomous access

Rookery intentionally launches Codex with full operator-account access:

```toml
approval_policy = "never"
sandbox_mode = "danger-full-access"
```

Review the complete files before launch:

```bash
cmp .codex/config.toml configs/codex-base.toml
sed -n '1,80p' configs/codex-base.toml
./go status
```

`./go status` is a pure read and an untouched extraction reports `uninitialized`. The Codex mode permits filesystem writes, process execution, and network access without per-action approval. Use it only for the authorized event and disposable workspace you just configured.

The checked-in Codex configuration carries a safe bootstrap thread cap. During
`./go`, Rookery renders `CODEX_SUBAGENT_THREADS=96` into the one Codex
session's `agents.max_concurrent_threads_per_session` and sets `max_depth = 2`.
The main coordinator is depth 0, challenge coordinators are depth 1, and their
workers are depth 2. `CONCURRENCY_MAX_WORKERS` separately limits registered
worker attempts.

## 9. Start and stop

The first consequential event action is explicit:

```bash
./go
```

After the launch gate, Rookery may write runtime state, perform enabled preparation, start a managed SearXNG service when authorized, access the selected adapter, render the active surface, and launch Codex.

During the event:

```bash
./go status
./go stop
```

For an externally supervised browser bridge, `./go stop` is only the Rookery
stop barrier. From the same immutable Windows bundle, run
`start-chrome-cdp.ps1 -Mode Stop` with the exact port, policy, and profile used
by Start. The guarded Stop validates the ownership record and process identities
before terminating anything. Confirm its ownership record and former listeners
are gone; Rookery status alone does not prove workstation teardown.

Read the [Operator guide](operator.md) before relying on lifecycle or stop output. Read [Preparation](preparation.md) when the start is blocked by a missing capability.

## Expected results and common failures

| Check | Success | If it fails |
| --- | --- | --- |
| Source-checkout validation | JSON contains `"ok": true` | Correct the reported source error. Do not build. |
| Configured-release validation | JSON contains `"ok": true` | Correct the reported `.env` or release error before creating a baseline. |
| Release build | JSON contains `"ok": true` and three artifact names | Remove runtime residue, fix the named contract, or choose an output directory without existing artifact names. |
| SHA-256 check | `<archive>: OK` | Discard the received set and re-establish trusted transfer. |
| Extraction | JSON contains `"ok": true` | Leave the failed destination unused and investigate the archive/manifest mismatch. |
| Baseline | JSON contains `"ok": true` | Correct configuration, scope, paths, or release binding before launch. |
| Browser bridge, when required | Start and Health return successful JSON for one release-bound bundle, policy, and profile tuple | Inspect `ssh_stderr_log`, confirm key-based SSH and host trust, then repair or replace the tuple without bypassing guarded ownership checks. |
| `./go` | Codex starts from `START_PROMPT.md` and status becomes `ready` | Read the bounded error and generated `PREPARATION.md` when present; correct the blocker and rerun. |

Do not extract over an existing workspace, copy old runtime state into a new release, or use candidate archive code to verify that same candidate. Those procedures break the release and evidence boundaries.
