# SkillBit adapter

The public adapter ID is `skillbit`. It uses a dedicated authenticated Chrome
profile, loopback CDP, and the sealed browser gateway for the SkillBit
competition UI hosted on the legacy MetaCTF account and competition origins.
The production `sync()` path establishes or refreshes the session, proves the
configured account and event card, opens that event's Problems view, and
returns normalized challenge rows.

## Configuration

Put live values in the installed workspace's private `.env`:

```dotenv
PLATFORM_ADAPTER=skillbit
SKILLBIT_URL=https://compete.metactf.com
SKILLBIT_LOGIN_ORIGIN=https://app.metactf.com
SKILLBIT_EVENT_ID=289
SKILLBIT_ACCOUNT_ID=
SKILLBIT_PARTICIPATION_MODE=individual
SKILLBIT_TEAM_NAME=
SKILLBIT_USER=
SKILLBIT_EMAIL=
SKILLBIT_PASSWORD=
BROWSER_MODE=cdp
BROWSER_CDP_URL=http://127.0.0.1:9001
BROWSER_GATEWAY_URL=http://127.0.0.1:9003
ADAPTER_CONFIG_BROWSER_SUPPORT_ORIGINS=["https://app.metactf.com","https://assets.metactf.com","https://ajax.googleapis.com","https://cdnjs.cloudflare.com","https://use.fontawesome.com","https://cdn.jsdelivr.net"]
ADAPTER_CONFIG_SESSION_LEASE_SECONDS=60
ADAPTER_CONFIG_TIMEOUT=45
ADAPTER_CONFIG_MAX_RESPONSE_BYTES=262144
ALLOWED_FILE_ORIGINS=https://compete.metactf.com/289/api/attachments/*,https://cfstatic.mctf.io/*,https://metactf-problems.s3.us-east-1.amazonaws.com/*,https://metachallenge-artifacts-158909019700-us-east-1-an.s3.amazonaws.com/*,https://static.metaproblems.com/*,https://metaproblems.com/*,https://cyberlabhost.com/*
```

`SKILLBIT_URL` is the exact scoring origin. `SKILLBIT_LOGIN_ORIGIN` is the
exact account origin. `SKILLBIT_EVENT_ID` is the numeric competition ID on the
authorized event card. `SKILLBIT_ACCOUNT_ID` is the numeric `uid` in that
card's signed handoff URL. Set `SKILLBIT_PARTICIPATION_MODE` to `individual` or
`team`; team mode also requires the operator-attested `SKILLBIT_TEAM_NAME`.
The release baseline binds that declaration to the account and event. Replace
`289` in the attachment pattern with the
configured event ID; do not authorize the entire competition origin as a file
source.

Put platform and support hosts in `PLATFORM_HOSTS`. Put only organizer-designated
challenge targets in `ALLOWED_HOSTS` or `ALLOWED_CIDRS`. The three identity and
password values establish the session and remain private workspace data.

## Browser bridge

Export a versioned browser bridge from the verified release, not from a mutable
source checkout. The bundle includes the Chrome helper, sealed gateway, and a
manifest that binds their hashes to the release. Follow the canonical
[browser bridge runbook](../../docs/browser_bridge.md) to export it, create the
release-bound policy, start it with the current WSL address, check health, stop
it by its ownership record, and run the restart drill.

Use a different dedicated Chrome profile and gateway policy for every event or
release tuple. A changed credential, account, event ID, origin, support-origin
list, attachment pattern, browser endpoint, release, or baseline requires a
fresh baseline and policy before the bridge starts.

## Session and registration state

`sync()` is the credential-capable refresh operation. It reuses a healthy
authenticated profile or performs one bounded login, then verifies:

- the dashboard identity matches `SKILLBIT_USER` exactly;
- exactly one dashboard event card links to the configured event;
- the handoff contains the expected signed parameters and its `uid` matches
  `SKILLBIT_ACCOUNT_ID`; and
- the handoff reaches the configured event's Problems route.

This event-card proof establishes account enrollment in the configured event.
Session state also reports the baseline-bound participation declaration. Team
mode is an operator attestation because the legacy competition UI exposes no
stable team or roster identifier. If the live event shows registration, team selection, SSO, or any
other interaction before the exact event card exists, the adapter reports that
state without performing the mutation. Complete that event-specific action
through the approved operator workflow, then run `sync()` again.

Action preflight and execution do not enter credentials. An expired session is
a failed action preflight with a refresh-required reason; run the production
`sync()` path to reauthenticate and reprove the account and event before
reviewing another action.

## Inventory and details

Inventory uses the page-owned `problems` registry. Challenge IDs must be unique
positive integers and all returned fields are bounded. Each row records its own
submission modality. A text input can be eligible for `flag` or `free_text`;
`multiple_choice`, `manual`, locked, and `unsupported` rows stay visible but
are non-submittable. Lab or instance shapes without the reviewed text contract
therefore remain `unsupported`. One unsupported row does not make the rest of
the inventory unhealthy.

`detail()` performs a fresh bounded read for one challenge. It preserves
bounded `description_text` and `description_html`, submission modality,
manual-grading fields, graded points, hints, penalties, ratings, tags, solve
count, solver and teammate solve state when the platform exposes them, and at
most 32 classified resources. `resources_complete` and `resources_truncated`
show whether that resource list is complete. Resource records distinguish
authenticated SkillBit attachments from other links. The adapter maps common
platform categories to Rookery categories, including `reverse` to `rev`,
`pcap` to `forensics`, `trivia` to `misc`, and `osint` to
`advanced-research`.

## Authenticated attachments

SkillBit marks authenticated download anchors with the `mctf-s3dl` CSS class.
The adapter confirms the root-relative URL has the configured event's exact
`/<event>/api/attachments/<token>/<filename>` shape, checks it against
`ALLOWED_FILE_ORIGINS`, obtains only
the cookies applicable to that exact URL from the owned browser target, and
streams the response through Rookery's scoped transport. Redirects are checked
again, and the compiled `SCOPE_MAX_BYTES` bound applies throughout the read.

Capture publishes a mode-`0600` private file without replacing an existing path
and returns bounded provenance including SHA-256, HTTP status, final URL,
content length, and optional content type, disposition, ETag, and last-modified
metadata. A cross-origin redirect is scoped again and loses the Cookie and
User-Agent headers. Reviewed public file and image origins may also be captured
without session cookies. General tools, social links, extensionless challenge
services, and other challenge targets stay non-capturable resources. Cookies
and handoff query values are not included in normalized challenge data or
capture evidence.

## Reviewed scoring

Solvers use `score-propose`. Independent review, current authorization, the
immutable execution plan, scope, and stop generation remain mandatory.

Preflight requires an existing authenticated session, the exact configured
account and event, an unsolved text-submission challenge, the prepared gateway,
and a short-lived one-use lease. A challenge already solved before dispatch is
reported as prior platform state; it is not proof that the proposed candidate
was accepted.

Execution passes the candidate as a typed CDP argument to fixed adapter code,
fills the bound challenge input, and invokes the platform submit method once.
The expected request is one `POST` to the configured event's `api/submit.php`
with the exact challenge ID and answer. There is no retry or alternate
transport after dispatch.

The platform response is interpreted narrowly:

- `success` is accepted scorer truth;
- `error` is rejected scorer truth; and
- `info`, missing or malformed responses, timeouts, redirects, and disconnects
  before a bound scorer response are indeterminate.

Evidence separates candidate clearing, duplicate interception, response
release, and owned-target teardown. A definitive bound scorer response remains
authoritative if later corroboration or teardown fails. A target that cannot be
confirmed closed is retained as explicit teardown debt and must be handled by
the guarded browser bridge stop workflow.
