# CTFd browser-session adapter

Use this adapter when an authorized CTFd event may use a direct CTFd token and
has an authenticated local Chromium CDP or Firefox WebDriver BiDi session for
the bounded cookie fallback.

Select it with `PLATFORM_ADAPTER=ctfd_browser` and set `CTFD_URL` to the event's
exact HTTPS origin. Choose one browser transport:

```dotenv
BROWSER_MODE=cdp
BROWSER_CDP_URL=http://127.0.0.1:9001
```

```dotenv
BROWSER_MODE=bidi
BROWSER_BIDI_URL=ws://127.0.0.1:9223/session
```

Rookery validates the selected loopback endpoint before launch. The selected
browser profile must already be authenticated and have exactly one top-level
page at the CTFd origin. `ADAPTER_CONFIG_TARGET_ID` selects that page's CDP
target ID or BiDi context ID when multiple matching pages are open.

The adapter reads only the matching page's user agent and applicable secure
cookies. CDP reads the user agent from browser metadata; BiDi reads the fixed
`navigator.userAgent` expression in an isolated realm. Neither path navigates,
clicks, executes arbitrary page code, or asks the browser to make a network
request.
It sends inventory reads, session verification, and reviewed flag submissions through Rookery's DNS-pinned scoped HTTP transport.
Cookies and user agents remain in memory and are excluded from execution evidence.

When private `.env` provides `CTFD_TOKEN`, the adapter first tries fixed bearer
GET requests for account, team when configured, and inventory. It selects the
existing cookie relay only after a clear authentication failure: HTTP 401/403,
a same-origin `/login` redirect, or a bounded HTML access page. Other token
read failures remain unhealthy. A successful token preflight creates a token
lease and sends one reviewed bearer POST; no timeout, HTTP response, malformed
response, or uncertain result can retry through the cookie session.

Put all operator configuration in the single private `.env`:

```dotenv
PLATFORM_ADAPTER=ctfd_browser
CTFD_URL=https://ctf.example
CTFD_TOKEN=
BROWSER_MODE=cdp
BROWSER_CDP_URL=http://127.0.0.1:9001
BROWSER_BIDI_URL=ws://127.0.0.1:9223/session
ADAPTER_CONFIG_BASE_URL=https://ctf.example
ADAPTER_CONFIG_SCORING_MODE=team
ADAPTER_CONFIG_EXPECTED_ACCOUNT_ID=1234
ADAPTER_CONFIG_EXPECTED_TEAM_ID=5678
ADAPTER_CONFIG_TARGET_ID=
ADAPTER_CONFIG_CSRF_PAGE_PATH=/challenges
ADAPTER_CONFIG_SESSION_LEASE_SECONDS=60
ADAPTER_CONFIG_TIMEOUT=30
ADAPTER_CONFIG_MAX_RESPONSE_BYTES=262144
ADAPTER_CONFIG_SEQUENTIAL_UNLOCK=0
```

`ADAPTER_CONFIG_BASE_URL` must agree with `CTFD_URL` when set.
Set `ADAPTER_CONFIG_SCORING_MODE` to exactly `user` or `team`; this assertion must match the event's actual CTFd mode, and the adapter does not infer it.
`ADAPTER_CONFIG_EXPECTED_ACCOUNT_ID` is required in both modes and must match the scoped `/api/v1/users/me` result.
Team mode also requires `ADAPTER_CONFIG_EXPECTED_TEAM_ID`, which must match `/api/v1/teams/me`; user mode rejects it.
Missing or mismatched identity configuration fails before inventory.
When more than one matching page is open, `ADAPTER_CONFIG_TARGET_ID` is required;
it changes when the browser creates a new target or context.
`ADAPTER_CONFIG_CSRF_PAGE_PATH` defaults to `/challenges`; override it only when the selected CTFd deployment exposes its nonce on another path using letters, digits, `/`, `_`, or `-`.

During preflight, the scoped transport performs a no-redirect GET for that HTML page and requires exactly one distinct `csrf_nonce` or `csrfNonce` value. Identical repeats are accepted; different values are ambiguous. The value must contain 16 to 256 letters, digits, `_`, `.`, or `-` characters.
A missing, ambiguous, invalid, non-HTML, or access-blocked nonce response marks inventory and scoring unhealthy before inventory or submission.
The nonce stays only in the in-memory session lease and is sent as `CSRF-Token` on the single reviewed attempt POST.

The session lease is held only between adapter preflight and the single reviewed submission, and expires before any later submission can occur.

## Optional sequential unlock mode

Set `ADAPTER_CONFIG_SEQUENTIAL_UNLOCK=1` when the selected CTFd event returns
explicit solve state and positions for accessible challenges. CTFd may also
return locked prerequisite previews with `type="hidden"`, no position or
module ID, and empty template and script fields. The adapter ignores only
that exact preview shape. It exposes the lowest-position accessible row whose
`solved_by_me` is `false` and binds its challenge ID into a one-use lease. A
proposal for an earlier or otherwise stale ID fails before submission.

The adapter does not infer a lock from a missing field alone. A malformed
hidden preview, a missing or malformed accessible position, duplicate
accessible positions, or a missing or non-boolean solve state fails the
inventory closed. Once every accessible row is solved, the inventory has no
visible challenge. A fresh synchronization after an accepted score exposes
the next unlocked, unsolved position.

Cloudflare or a similar service can bind clearance to the browser's TLS fingerprint or source connection.
If the scoped HTTP request does not pass using the cookie-derived session, this adapter reports unhealthy scoring and does not submit through Chrome.
