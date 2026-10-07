# Preparation

Rookery discovers required local capabilities and can fill declared gaps after the launch gate passes. It never guesses event configuration and never enables package or image downloads without explicit operator opt-in.

## Contents

- [Before preparation](#before-preparation)
- [Preparation modes](#preparation-modes)
- [Generated preparation state](#generated-preparation-state)
- [SearXNG](#searxng)
- [Browser and VPN](#browser-and-vpn)
- [Failure behavior](#failure-behavior)

## Before preparation

Complete [Getting started](getting-started.md) through configuration and baseline creation first. `./go` checks the event, acknowledged scope, baseline, selected adapter, Codex executable, login, and authentication capability before preparation can write runtime state or use adapter access.

Both validation modes are read-only. Use the explicit source mode before a build:

```bash
PYTHONDONTWRITEBYTECODE=1 ./bin/rookery validate --release --source-checkout
```

After verified extraction, require the installed live configuration files:

```bash
PYTHONDONTWRITEBYTECODE=1 ./bin/rookery validate --release
```

Use [Configuration](configuration.md) to edit the private `.env`. The dotenv parser treats assignments as bounded literal data. It does not evaluate shell expansion, substitutions, or commands. Duplicate, malformed, undeclared, and unselected-adapter assignments fail closed.

## Preparation modes

Set `ROOKERY_PREPARE_MODE` in `.env`:

| Mode | Behavior |
| --- | --- |
| `auto` | Discover capabilities and, when separately authorized, install declared packages or start managed SearXNG. |
| `check` | Inspect capabilities without package installation or managed service startup. |
| `off` | Skip installation and service startup while retaining the declared operator intent. |

The default network gate is closed:

```dotenv
ROOKERY_PREPARE_INSTALL=1
ROOKERY_INSTALL_RECOMMENDED=1
ROOKERY_INSTALL_HEAVY=0
ROOKERY_ALLOW_INSTALL_NETWORK=0
```

With `ROOKERY_ALLOW_INSTALL_NETWORK=0`, Rookery does not download packages or pull images. Missing required commands become visible preparation blockers. Set it to `1` only for a deliberate networked preparation run within the event and environment authorization.

The declarative inventory is [`configs/preparation.json`](../configs/preparation.json). `bash` and Python 3.11 or newer must already exist because Rookery needs them before it can prepare anything.

## Generated preparation state

After the launch gate succeeds, preparation writes:

- `state/preparation.json` for machine-readable status;
- `state/prepared.env` for discovered non-secret paths and endpoints; and
- `PREPARATION.md` for the current operator and agent summary.

`PREPARATION.md` is the authority for which optional analysis tools are usable
in that runtime. A documented wrapper or registry entry does not make its
external command or data dependency available.

Child processes receive a minimal environment plus keys explicitly declared for their purpose. Adapter, session, VPN, and provider credentials are not passed to unrelated tools or Codex.

## SearXNG

When `SEARXNG_URL` is set, Rookery health-checks and uses that external endpoint unchanged. When it is empty and `SEARXNG_MODE=auto`, Rookery may start a project-owned, loopback-only container only after network installation is enabled. The image must match the exact reviewed reference and digest in `.env.example`.

Rookery records image identity; it does not claim that the digest authenticates the publisher. A configured proxy is accepted only when the scoped transport can retain its direct pinned route. Otherwise the health check fails before network or evidence effects.

## Browser and VPN

`BROWSER_MODE=cdp` requires `BROWSER_CDP_URL` to be an explicit HTTP URL on `127.0.0.1`, including its port. Before any event state is written, Rookery reads only the bounded `/json/version` document, without a proxy or redirects, and verifies that Chrome advertises a WebSocket endpoint on the same loopback port. A selected adapter may require this check regardless of the general browser mode.

`BROWSER_MODE=bidi` requires `BROWSER_BIDI_URL` to be an exact
`ws://127.0.0.1:<port>/session` URL. Rookery opens a bounded WebSocket
connection, proves that the server is Firefox, and ends the temporary BiDi
session before launch state is written. The current complete adapter path is
`ctfd_browser`; its browser session and scoring rules remain in that adapter.
The BiDi endpoint is an external browser capability, so no Chrome bridge is
needed for that mode.

For `ctfd_browser_gateway`, finish both transports before creating the baseline. Keep `CTFD_TOKEN` private in `.env`; set `ADAPTER_CONFIG_TOKEN_ENV`, `ADAPTER_CONFIG_BASE_URL`, `ADAPTER_CONFIG_SCORING_MODE`, and `ADAPTER_CONFIG_EXPECTED_ACCOUNT_ID` there too, with `ADAPTER_CONFIG_EXPECTED_TEAM_ID` present only in team mode. Keep `CTFD_NETWORK_ENV_KEYS=[]` unless the scoped token route deliberately needs reviewed proxy or CA environment names. Set the loopback CDP and gateway-status URLs, declare support origins in `ADAPTER_CONFIG_BROWSER_SUPPORT_ORIGINS`, and authorize their hosts in `PLATFORM_HOSTS`. The baseline binds configuration and availability facts without retaining the token value.

The adapter always requires verified CDP and sealed-gateway readiness even though its read-only preflight tries the scoped token route first. This keeps Chrome ready for the narrow fallback conditions established before launch. A fixed token read may select Chrome only after HTTP 401 or 403, a bounded successful HTML interstitial, one exact-origin access redirect, or a typed DNS, connection, or timeout failure. A missing token, invalid token selector, configuration or scope error, TLS validation failure, account or team mismatch, malformed successful JSON, HTTP 404 or 429, server failure, or cross-origin redirect blocks the adapter instead.

For `skillbit`, confirm before baseline creation that the operator's event authority permits the stated human and AI partnership and the adapter's bounded UI automation. Configure the exact scoring origin, account origin, numeric event ID, numeric account ID from the event card's signed handoff URL, platform support origins, and the private `SKILLBIT_USER`, `SKILLBIT_PASSWORD`, and `SKILLBIT_EMAIL` values in `.env`. Put every platform and support host in `PLATFORM_HOSTS`, while keeping organizer-designated challenge targets in `ALLOWED_HOSTS` or `ALLOWED_CIDRS`. Add the configured event's exact `https://<scoring-origin>/<event-id>/api/attachments/*` pattern plus reviewed public asset patterns to `ALLOWED_FILE_ORIGINS`. The `mctf-s3dl` marker is an anchor class; it is not a filename suffix.

Prepare `skillbit` with the dedicated Chrome profile and sealed gateway even when that profile already has an authenticated session. Export its release-bound gateway policy after the baseline and export the browser bridge from the same verified release. Transfer the exact bundle and policy privately to the workstation, then use the [browser bridge runbook](browser_bridge.md) for start and health. The gateway admits only the configured scoring, login, and support origins. The adapter further limits its top-level CDP flow to login, account verification, the configured event handoff, the Problems view, bounded inventory and detail reads, authenticated attachment capture, and one reviewed scoring attempt.

Run the production adapter `sync()` after bridge health succeeds. A healthy sync proves the configured account identity, exactly one configured event card, its account-bound signed handoff, and the Problems route. That is the available registration proof. The private baseline also binds an operator participation attestation: individual mode, or team mode with the expected team name. Registration, team selection, SSO, or another unexpected interaction is an operator-visible state rather than an adapter mutation. After the operator completes any required event-specific interaction, run `sync()` again. The same path refreshes an expired login without submitting an answer.

For a remote Linux or WSL Rookery workspace and a Windows workstation, first
export the immutable bridge from the verified release, then run it from that
bundle. Do not start the gateway or Chrome helper from a mutable source
checkout. The [browser bridge runbook](browser_bridge.md) provides the exact
export, start, health, guarded stop, side-by-side upgrade, and restart drill.
The helper resolves the current WSL address at start when a distribution and
user are supplied, so a stale address is never treated as durable
configuration. Set the remote `.env` to:

```dotenv
BROWSER_MODE=cdp
BROWSER_CDP_URL=http://127.0.0.1:9001
# Required only by a selected sealed-gateway adapter:
BROWSER_GATEWAY_URL=http://127.0.0.1:9003
```

For a browser-session adapter, authenticate and arrange tabs exactly as its
local README requires. Keep the bridge ownership record and its processes open
for the event. After `./go stop`, use the bundle's guarded stop mode and then
run its read-only health mode to verify that the owned listeners are gone.

For `skillbit`, this guarded bridge shutdown is the required session teardown.
Do not carry the authenticated profile, policy, gateway, tunnel, or listeners
into a differently configured event. A credential, identity, event, origin,
support-origin, attachment-origin, release, or browser-endpoint change requires
the side-by-side workspace, profile, baseline, policy, and bridge replacement
described in [Configuration](configuration.md) and [Browser bridge](browser_bridge.md).

During event execution, the token-first choice is read-only preflight state rather than action authority. A scoring POST still requires a proposal, independent review, current authorization, and the stop-generation check. If a token POST begins, Rookery never attempts a second POST through Chrome, including after a timeout, reset, HTTP error, invalid body, or ambiguous verdict.

`BROWSER_MODE=auto` retains existing-browser discovery for operator-side research. `BROWSER_EXECUTABLE` or `CHROME_BIN` can select that executable. Rookery does not download a browser and does not provide generic browser navigation, capture, or submission automation.

VPN setup and supervision are external in this release. Establish any authorized VPN before Rookery starts. Rookery does not claim, monitor, or stop that external process.

## Failure behavior

Package-manager, installer, container, and discovery subprocesses use argument arrays without a shell and share bounded output and timeout controls. Missing optional capabilities remain visible gaps; agents can continue with available local tools. Missing required capabilities keep the workspace blocked.

Read `PREPARATION.md` after a failed start, correct the named capability or configuration, and rerun `./go`. CDP failures use `browser_cdp_url_invalid`, `browser_cdp_unreachable`, `browser_cdp_redirected`, `browser_cdp_response_too_large`, or `browser_cdp_invalid_response`. BiDi failures use `browser_bidi_url_invalid`, `browser_bidi_unreachable`, `browser_bidi_browser_invalid`, `browser_bidi_timeout`, or another bounded `browser_bidi_*` protocol result. An unsupported mode uses `browser_mode_invalid`. Confirm the selected browser service is still running, its loopback port is reachable, and both ends use the same endpoint. For adapter-specific session or platform failures, follow the selected adapter's local README rather than bypassing access controls. Do not treat `./go status` as a repair action; it is always a pure read.

For `skillbit`, use the adapter's read-only `session_health()` to distinguish a
missing login, identity mismatch, missing or ambiguous event registration,
browser failure, and gateway failure. A missing login is recovered only by the
credential-capable production `sync()` path. Registration or team interaction
remains an operator action; team state uses the baseline-bound operator attestation until SkillBit exposes
a stable field. Repeat health and `sync()` after recovery before proposing an
action.
