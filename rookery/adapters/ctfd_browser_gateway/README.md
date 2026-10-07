# CTFd token-primary adapter with sealed browser fallback

`ctfd_browser_gateway` is the selected CTFd adapter when the event has both an
official CTFd access token and a prepared, authenticated Chrome session. It
uses the token for normal scoped CTFd API reads and for one reviewed flag
submission. The sealed Chrome gateway is prepared before launch and becomes the
only fallback when a token **read** encounters a narrow access or route failure.

The adapter ID stays `ctfd_browser_gateway` for the event, proposal, review,
authorization, plan, execution, and reconciliation records. `token` and
`browser_gateway` are internal one-use transport choices; they do not change
scope or scoring authority.

## Configure and start

Set `PLATFORM_ADAPTER=ctfd_browser_gateway`, the exact HTTPS `CTFD_URL`, and
`CTFD_TOKEN` in the private `.env`. Set `BROWSER_MODE=cdp`,
`BROWSER_CDP_URL`, and `BROWSER_GATEWAY_URL` too. The two browser endpoint URLs
must be loopback URLs on the Rookery host, normally reverse SSH forwards to the
operator workstation.

`CTFD_TOKEN` is required. Its value is used only inside the selected adapter as
the CTFd `Authorization: Token` credential, as described in the [CTFd API
guide](https://docs.ctfd.io/docs/api/getting-started/). Do not put it in an
`ADAPTER_CONFIG_*` field, report, prompt, or command line. `CTFD_NETWORK_ENV_KEYS` is an
optional JSON array of exact proxy or CA environment key names for the token
transport. An empty array keeps those overrides out of the adapter. The scoped
transport pins the destination and refuses a proxy route that cannot retain its
direct pinned connection.

1. Configure the event scope, selected adapter, exact origin, scoring mode, and
   expected identity. Create the baseline only after those values are final.
2. On the Rookery host, export a new private gateway policy outside the source
   and release tree:

   ```bash
   ./bin/browser-gateway-policy --origin https://ctf.example --output /absolute/private/browser-gateway-policy.json
   ```

3. Transfer those exact private bytes through the operator's authenticated
   private channel to a new private Windows path. Do not put the policy in Git,
   a runtime log, `.env`, or a shared directory.
4. Export an immutable browser bridge from the verified release archive and
   manifest as described in the [browser bridge runbook](../../docs/browser_bridge.md).
   Transfer that exact bundle to a new private Windows path, then start the
   dedicated proxy-bound Chrome profile and reverse forwards from the bundle:

   ```powershell
   & '<absolute-windows-bundle>\bin\start-chrome-cdp.ps1' `
     -Mode Start `
     -SshTarget '<remote-user>@<remote-host>' `
     -GatewayPolicyPath '<absolute-windows-policy-path>' `
     -UserDataDir '<new-dedicated-profile-path>'
   ```

5. Authenticate exactly one CTFd page in that Chrome profile. Close the
   initial blank page and unrelated page or worker targets.
6. Run `./go` when event launch is authorized. CDP and the sealed gateway are
   verified before any token read, including runs that ultimately use only the
   token transport.
7. At closeout, run `./go stop`, then use the same immutable bundle, policy,
   profile, and port with `start-chrome-cdp.ps1 -Mode Stop`. The guarded Stop
   verifies the ownership record before terminating anything. Confirm the
   ownership record and forwarded listeners are gone.

The reverse-forwarded CDP and gateway status endpoints are unauthenticated
loopback listeners on the remote node. Use this mode with one trusted operator
on a trusted workstation and remote host, or provide authenticated per-user
isolation outside Rookery.

## Private `.env` configuration

Put the stable identity assertions and both transport configurations in the single private `.env`:

```dotenv
PLATFORM_ADAPTER=ctfd_browser_gateway
CTFD_URL=https://ctf.example
CTFD_TOKEN=
CTFD_NETWORK_ENV_KEYS=[]
BROWSER_MODE=cdp
BROWSER_CDP_URL=http://127.0.0.1:9001
BROWSER_GATEWAY_URL=http://127.0.0.1:9003
ADAPTER_CONFIG_BASE_URL=https://ctf.example
ADAPTER_CONFIG_TOKEN_ENV=CTFD_TOKEN
ADAPTER_CONFIG_SCORING_MODE=team
ADAPTER_CONFIG_EXPECTED_ACCOUNT_ID=1234
ADAPTER_CONFIG_EXPECTED_TEAM_ID=5678
ADAPTER_CONFIG_CSRF_PAGE_PATH=/challenges
ADAPTER_CONFIG_SESSION_LEASE_SECONDS=60
ADAPTER_CONFIG_TIMEOUT=30
ADAPTER_CONFIG_MAX_RESPONSE_BYTES=262144
ADAPTER_CONFIG_BROWSER_SUPPORT_ORIGINS=["https://challenges.cloudflare.com"]
```

`ADAPTER_CONFIG_BASE_URL` must be the exact lower-case CTFd HTTPS origin on port 443 and must
agree with `CTFD_URL`. `ADAPTER_CONFIG_TOKEN_ENV` names `CTFD_TOKEN` by default.
Set `ADAPTER_CONFIG_SCORING_MODE` to `user` or `team` explicitly. `ADAPTER_CONFIG_EXPECTED_ACCOUNT_ID` is
required in both modes. Team mode also requires `ADAPTER_CONFIG_EXPECTED_TEAM_ID`; user mode
rejects it.

`ADAPTER_CONFIG_BROWSER_SUPPORT_ORIGINS` admits only exact platform-scoped HTTPS origins to
the gateway policy, such as a reviewed Cloudflare challenge host. It does not
make them CTFd API targets. The adapter sends its fixed account, team,
anti-forgery, inventory, and attempt paths only to the resolved `ADAPTER_CONFIG_BASE_URL` origin.
Authorize every support origin's host separately in `PLATFORM_HOSTS` before the baseline.

## Transport selection and scoring

During read-only preflight, the adapter first verifies the CDP endpoint and
gateway policy, boot nonce, expiry, scope, and origin. It then uses the token
for fixed, scoped GET requests to `/api/v1/users/me`, `/api/v1/teams/me` in
team mode, and `/api/v1/challenges`. Every successful response must be bounded
JSON with `success: true` and the exact configured account and team identity.

The adapter selects the sealed Chrome route only if one of those token reads
gets a 401 or 403, a bounded HTML access interstitial, a same-origin login
redirect to the fixed `/login` path, or a DNS, connection, or timeout failure.
The Chrome route creates a
fresh owned target, rechecks the browser account and team, obtains a fresh CSRF
value, reads inventory, and closes its target without reusing or closing the
operator authentication tab. A healthy browser fallback is visible as degraded
capability health with `token_primary_unavailable; browser_fallback_ready`.

Missing or malformed token configuration, certificate failures, scope or origin
drift, identity mismatch, malformed successful API data, cross-origin
redirects, 404, 429, and server errors are terminal preflight failures. They do
not select Chrome.

Each preflight creates one in-memory lease bound to the canonical origin,
semantic scope digest, configured identity, gateway policy digest and boot
nonce, and, for the token route, a private token/config fingerprint. It expires
after `session_lease_seconds` or one action. The generic executor still owns
independent review, authorization, the final stop-generation check, and scorer
truth recording.

After authority is claimed, a token lease performs only a local fingerprint
check and one exact `POST /api/v1/challenges/attempt`; it does not make another
identity GET. Once that POST starts, no HTTP response, timeout, connection
failure, malformed body, or ambiguous verdict can fall back to Chrome. The
result remains an indeterminate potentially committed attempt until scorer
truth is established. The browser lease retains its fresh-target one-POST
check, gateway transfer evidence, and fail-closed scorer behavior.

CTFd scorer truth is taken only from its fixed `data.status` values `correct`,
`incorrect`, and `already_solved` (with the compatible `correct` boolean where
present). Free-form messages and statuses such as `partial`, `ratelimited`,
`paused`, and `authentication_required` are indeterminate. They never become a
solve or rejection by matching words in explanatory text.

Private execution evidence retains the exact candidate, canonical request
metadata, bounded scorer response, selected transport, and typed verdict. It
omits the token, Authorization header, cookies, CSRF value, CDP and gateway
URLs, gateway boot nonce, and token fingerprint. Browser evidence retains the
non-secret semantic gateway policy SHA-256 as its binding proof.
